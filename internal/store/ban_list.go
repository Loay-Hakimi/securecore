package store

import (
	"math"
	"sync"
	"time"
)

type banEntry struct {
	until    time.Time
	offenses int
}

// BanList is a concurrency-safe registry of temporarily banned IPs with
// per-IP TTLs and escalating ban durations for repeat offenders.
type BanList struct {
	mu   sync.RWMutex
	bans map[string]banEntry
	now  func() time.Time
}

// NewBanList returns an empty ban list.
func NewBanList() *BanList {
	return &BanList{bans: make(map[string]banEntry), now: time.Now}
}

// Ban bans ip for base duration, scaled by escalation^(prior offenses) when
// escalation > 1. It returns the time at which the ban expires. Write lock.
func (b *BanList) Ban(ip string, base time.Duration, escalation float64) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()

	e := b.bans[ip]
	dur := base
	if escalation > 1 && e.offenses > 0 {
		dur = time.Duration(float64(base) * math.Pow(escalation, float64(e.offenses)))
	}
	e.offenses++
	e.until = b.now().Add(dur)
	b.bans[ip] = e
	return e.until
}

// Banned reports whether ip is currently banned and, if so, the time
// remaining on the ban. Read lock.
func (b *BanList) Banned(ip string) (bool, time.Duration) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	e, ok := b.bans[ip]
	if !ok {
		return false, 0
	}
	rem := e.until.Sub(b.now())
	if rem <= 0 {
		return false, 0
	}
	return true, rem
}

// Cleanup removes expired bans and returns how many were removed. Write lock.
func (b *BanList) Cleanup() int {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()

	removed := 0
	for ip, e := range b.bans {
		if e.until.Before(now) {
			delete(b.bans, ip)
			removed++
		}
	}
	return removed
}

// Size returns the number of tracked (active or expired-but-not-cleaned) bans.
func (b *BanList) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.bans)
}
