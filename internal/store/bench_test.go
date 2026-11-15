package store

import (
	"testing"
	"time"
)

// BenchmarkAllow isolates the rate-limiter decision cost (lock + window prune +
// append) with a 1ns window so the per-IP window stays at size ~1.
func BenchmarkAllow(b *testing.B) {
	s := NewIPStore(1, time.Nanosecond)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Allow("10.0.0.1")
		}
	})
}
