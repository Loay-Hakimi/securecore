package store

import (
	"sync"
	"testing"
	"time"
)

func TestIPStoreAllowWithinLimit(t *testing.T) {
	s := NewIPStore(3, time.Minute)
	for i := 0; i < 3; i++ {
		if ok, _ := s.Allow("1.2.3.4"); !ok {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if ok, retry := s.Allow("1.2.3.4"); ok || retry <= 0 {
		t.Fatalf("4th request should be denied with positive retry, got ok=%v retry=%v", ok, retry)
	}
}

func TestIPStoreIsolatesIPs(t *testing.T) {
	s := NewIPStore(1, time.Minute)
	if ok, _ := s.Allow("1.1.1.1"); !ok {
		t.Fatal("first IP first request should pass")
	}
	if ok, _ := s.Allow("2.2.2.2"); !ok {
		t.Fatal("second IP should have its own budget")
	}
	if ok, _ := s.Allow("1.1.1.1"); ok {
		t.Fatal("first IP second request should be denied")
	}
}

func TestIPStoreWindowSlides(t *testing.T) {
	now := time.Now()
	s := NewIPStore(1, 100*time.Millisecond)
	s.now = func() time.Time { return now }

	if ok, _ := s.Allow("9.9.9.9"); !ok {
		t.Fatal("first request should pass")
	}
	if ok, _ := s.Allow("9.9.9.9"); ok {
		t.Fatal("second request in-window should fail")
	}
	// Advance past the window.
	now = now.Add(200 * time.Millisecond)
	if ok, _ := s.Allow("9.9.9.9"); !ok {
		t.Fatal("request after window should pass again")
	}
}

func TestIPStoreCleanup(t *testing.T) {
	now := time.Now()
	s := NewIPStore(5, 50*time.Millisecond)
	s.now = func() time.Time { return now }
	s.Allow("5.5.5.5")
	if s.TrackedIPs() != 1 {
		t.Fatalf("expected 1 tracked IP, got %d", s.TrackedIPs())
	}
	now = now.Add(time.Second)
	if removed := s.Cleanup(); removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
	if s.TrackedIPs() != 0 {
		t.Fatalf("expected 0 tracked IPs after cleanup, got %d", s.TrackedIPs())
	}
}

// TestIPStoreConcurrent exercises the RWMutex under -race.
func TestIPStoreConcurrent(t *testing.T) {
	s := NewIPStore(1_000_000, time.Minute)
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := string(rune('A'+id%5)) + ".0.0.1"
			for i := 0; i < 200; i++ {
				s.Allow(ip)
				s.Count(ip)
			}
		}(g)
	}
	wg.Wait()
}
