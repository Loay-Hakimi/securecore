package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Loay-Hakimi/securecore/internal/store"
)

// globalCounter is a fixed-window (1 second) global request counter.
type globalCounter struct {
	mu    sync.Mutex
	sec   int64
	count int64
	now   func() time.Time
}

func (g *globalCounter) incr() int64 {
	s := g.now().Unix()
	g.mu.Lock()
	defer g.mu.Unlock()
	if s != g.sec {
		g.sec = s
		g.count = 0
	}
	g.count++
	return g.count
}

// DDoSGuard is middleware that rejects traffic once a global per-second ceiling
// is breached and temporarily bans any single IP that exceeds a per-IP request
// threshold within a short window. Bans escalate for repeat offenders.
type DDoSGuard struct {
	enabled      bool
	banList      *store.BanList
	ipTracker    *store.IPStore
	globalCeil   int64
	counter      *globalCounter
	banDuration  time.Duration
	escalation   float64
}

// NewDDoSGuard builds a guard. perIPThreshold requests within banWindow trigger
// a ban of banDuration (escalated by escalation^offenses). A globalCeil of 0
// disables the global ceiling.
func NewDDoSGuard(enabled bool, globalCeil int64, perIPThreshold int, banWindow, banDuration time.Duration, escalation float64) *DDoSGuard {
	return &DDoSGuard{
		enabled:     enabled,
		banList:     store.NewBanList(),
		ipTracker:   store.NewIPStore(perIPThreshold, banWindow),
		globalCeil:  globalCeil,
		counter:     &globalCounter{now: time.Now},
		banDuration: banDuration,
		escalation:  escalation,
	}
}

// BanList exposes the underlying ban registry (used by the cleanup worker).
func (d *DDoSGuard) BanList() *store.BanList { return d.banList }

// Handler wraps next with DDoS protection.
func (d *DDoSGuard) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.enabled {
			next.ServeHTTP(w, r)
			return
		}
		ip := ClientIP(r)

		// Already banned? Reject immediately.
		if banned, rem := d.banList.Banned(ip); banned {
			w.Header().Set("Retry-After", strconv.Itoa(int(rem.Seconds())+1))
			http.Error(w, "403 Forbidden: temporarily banned", http.StatusForbidden)
			return
		}

		// Global per-second ceiling.
		if d.globalCeil > 0 && d.counter.incr() > d.globalCeil {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "503 Service Unavailable: global rate ceiling", http.StatusServiceUnavailable)
			return
		}

		// Per-IP burst threshold — exceeding it earns a temporary ban.
		if ok, _ := d.ipTracker.Allow(ip); !ok {
			until := d.banList.Ban(ip, d.banDuration, d.escalation)
			rem := until.Sub(time.Now())
			w.Header().Set("Retry-After", strconv.Itoa(int(rem.Seconds())+1))
			http.Error(w, "403 Forbidden: request rate triggered a temporary ban", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
