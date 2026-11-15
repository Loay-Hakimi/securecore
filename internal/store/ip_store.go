// Package store provides concurrency-safe in-memory state for the gateway:
// a per-IP sliding-window request counter and a temporary ban registry.
package store

import (
	"sync"
	"time"
)

// IPStore tracks recent request timestamps per client IP for sliding-window
// rate limiting. It is safe for concurrent use: reads take a read lock and
// mutations take a write lock on a sync.RWMutex.
type IPStore struct {
	mu      sync.RWMutex
	windows map[string][]time.Time
	window  time.Duration
	limit   int
	now     func() time.Time
}

// NewIPStore returns a store that allows up to limit requests per IP within
// the given window.
func NewIPStore(limit int, window time.Duration) *IPStore {
	return &IPStore{
		windows: make(map[string][]time.Time),
		window:  window,
		limit:   limit,
		now:     time.Now,
	}
}

// prune removes timestamps older than the window from s (caller holds the lock).
func pruneBefore(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for ; i < len(times); i++ {
		if times[i].After(cutoff) {
			break
		}
	}
	return times[i:]
}

// Allow records a request from ip and reports whether it is within the limit.
// When the limit is exceeded it returns false and the duration until the
// oldest in-window request expires (a Retry-After hint). Takes the write lock.
func (s *IPStore) Allow(ip string) (bool, time.Duration) {
	now := s.now()
	cutoff := now.Add(-s.window)

	s.mu.Lock()
	defer s.mu.Unlock()

	times := pruneBefore(s.windows[ip], cutoff)
	if len(times) >= s.limit {
		retry := times[0].Add(s.window).Sub(now)
		s.windows[ip] = times
		if retry < 0 {
			retry = 0
		}
		return false, retry
	}
	s.windows[ip] = append(times, now)
	return true, 0
}

// Count returns the number of in-window requests recorded for ip. It takes a
// read lock, demonstrating non-blocking concurrent lookups.
func (s *IPStore) Count(ip string) int {
	now := s.now()
	cutoff := now.Add(-s.window)

	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.windows[ip] {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// Cleanup drops entries whose timestamps have all expired, freeing memory for
// IPs that have gone quiet. Returns the number of IPs removed. Takes the write
// lock.
func (s *IPStore) Cleanup() int {
	now := s.now()
	cutoff := now.Add(-s.window)

	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for ip, times := range s.windows {
		pruned := pruneBefore(times, cutoff)
		if len(pruned) == 0 {
			delete(s.windows, ip)
			removed++
		} else {
			s.windows[ip] = pruned
		}
	}
	return removed
}

// TrackedIPs returns how many distinct IPs currently hold state. Read lock.
func (s *IPStore) TrackedIPs() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.windows)
}
