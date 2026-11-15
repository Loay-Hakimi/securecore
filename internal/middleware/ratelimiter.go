package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Loay-Hakimi/securecore/internal/store"
)

// RateLimiter is middleware that enforces a per-IP sliding-window request
// limit backed by a store.IPStore. Whitelisted IPs bypass the limit.
type RateLimiter struct {
	enabled   bool
	store     *store.IPStore
	whitelist *Whitelist
	limit     int
}

// NewRateLimiter builds a RateLimiter allowing limit+burst requests per window
// for any single non-whitelisted IP.
func NewRateLimiter(enabled bool, limit, burst int, window time.Duration, whitelist *Whitelist) *RateLimiter {
	capacity := limit + burst
	return &RateLimiter{
		enabled:   enabled,
		store:     store.NewIPStore(capacity, window),
		whitelist: whitelist,
		limit:     capacity,
	}
}

// Store exposes the underlying IPStore (used by the background cleanup worker).
func (rl *RateLimiter) Store() *store.IPStore { return rl.store }

// Handler wraps next with per-IP rate limiting.
func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.enabled {
			next.ServeHTTP(w, r)
			return
		}
		ip := ClientIP(r)
		if rl.whitelist != nil && rl.whitelist.Allowed(ip) {
			next.ServeHTTP(w, r)
			return
		}
		allowed, retry := rl.store.Allow(ip)
		if !allowed {
			secs := int(retry.Seconds())
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.limit))
			w.Header().Set("X-RateLimit-Remaining", "0")
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
