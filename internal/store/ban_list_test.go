package store

import (
	"testing"
	"time"
)

func TestBanListBanAndExpiry(t *testing.T) {
	now := time.Now()
	b := NewBanList()
	b.now = func() time.Time { return now }

	b.Ban("1.2.3.4", 10*time.Second, 1.0)
	if banned, rem := b.Banned("1.2.3.4"); !banned || rem <= 0 {
		t.Fatalf("expected active ban, got banned=%v rem=%v", banned, rem)
	}
	now = now.Add(11 * time.Second)
	if banned, _ := b.Banned("1.2.3.4"); banned {
		t.Fatal("ban should have expired")
	}
}

func TestBanListEscalation(t *testing.T) {
	now := time.Now()
	b := NewBanList()
	b.now = func() time.Time { return now }

	u1 := b.Ban("8.8.8.8", 10*time.Second, 2.0) // offense 1 -> base (10s)
	if got := u1.Sub(now); got != 10*time.Second {
		t.Fatalf("first ban should be 10s, got %v", got)
	}
	u2 := b.Ban("8.8.8.8", 10*time.Second, 2.0) // offense 2 -> 10s * 2^1 = 20s
	if got := u2.Sub(now); got != 20*time.Second {
		t.Fatalf("second ban should escalate to 20s, got %v", got)
	}
	u3 := b.Ban("8.8.8.8", 10*time.Second, 2.0) // offense 3 -> 10s * 2^2 = 40s
	if got := u3.Sub(now); got != 40*time.Second {
		t.Fatalf("third ban should escalate to 40s, got %v", got)
	}
}

func TestBanListUnknownNotBanned(t *testing.T) {
	b := NewBanList()
	if banned, _ := b.Banned("0.0.0.0"); banned {
		t.Fatal("unknown IP should not be banned")
	}
}

func TestBanListCleanup(t *testing.T) {
	now := time.Now()
	b := NewBanList()
	b.now = func() time.Time { return now }
	b.Ban("1.1.1.1", time.Second, 1.0)
	now = now.Add(2 * time.Second)
	if removed := b.Cleanup(); removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
	if b.Size() != 0 {
		t.Fatalf("expected empty ban list, got size %d", b.Size())
	}
}
