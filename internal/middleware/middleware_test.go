package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Loay-Hakimi/securecore/internal/config"
)

// okHandler is a trivial upstream that returns 200 OK.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "ok")
})

func newRequest(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	r.RemoteAddr = ip + ":40000"
	return r
}

func TestClientIP(t *testing.T) {
	r := newRequest("203.0.113.9")
	if got := ClientIP(r); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want 203.0.113.9", got)
	}
}

func TestWhitelist(t *testing.T) {
	wl := NewWhitelist([]string{"127.0.0.1", "10.0.0.0/8"})
	cases := map[string]bool{
		"127.0.0.1": true,
		"10.1.2.3":  true,
		"11.0.0.1":  false,
		"8.8.8.8":   false,
	}
	for ip, want := range cases {
		if got := wl.Allowed(ip); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	rl := NewRateLimiter(true, 2, 0, time.Minute, NewWhitelist(nil))
	h := rl.Handler(okHandler)

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newRequest("198.51.100.5"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRequest("198.51.100.5"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request: got %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
}

func TestRateLimiterWhitelistBypass(t *testing.T) {
	rl := NewRateLimiter(true, 1, 0, time.Minute, NewWhitelist([]string{"127.0.0.1"}))
	h := rl.Handler(okHandler)
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newRequest("127.0.0.1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("whitelisted request %d blocked with %d", i+1, rec.Code)
		}
	}
}

func TestDDoSGuardBansAfterThreshold(t *testing.T) {
	guard := NewDDoSGuard(true, 0, 3, time.Minute, 15*time.Minute, 2.0)
	h := guard.Handler(okHandler)

	// 3 allowed, 4th trips the ban.
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newRequest("192.0.2.7"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d got %d, want 200", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRequest("192.0.2.7"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("over-threshold request got %d, want 403", rec.Code)
	}
	// Subsequent requests remain banned.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, newRequest("192.0.2.7"))
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("banned IP got %d, want 403", rec2.Code)
	}
}

func TestDDoSGuardGlobalCeiling(t *testing.T) {
	guard := NewDDoSGuard(true, 2, 1_000_000, time.Minute, time.Minute, 1.0)
	h := guard.Handler(okHandler)
	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newRequest("203.0.113.50"))
		codes = append(codes, rec.Code)
	}
	if codes[0] != 200 || codes[1] != 200 {
		t.Fatalf("first two requests should pass, got %v", codes)
	}
	if codes[2] != http.StatusServiceUnavailable {
		t.Fatalf("third request should hit global ceiling (503), got %d", codes[2])
	}
}

func TestSecurityHeadersInjected(t *testing.T) {
	sh := NewSecurityHeaders(config.Default().SecurityHeaders)
	h := sh.Handler(okHandler)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRequest("1.2.3.4"))

	want := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Content-Security-Policy",
		"Referrer-Policy",
		"X-XSS-Protection",
		"Permissions-Policy",
	}
	for _, key := range want {
		if rec.Header().Get(key) == "" {
			t.Errorf("missing security header %q", key)
		}
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestLoggerRedactsAndChains(t *testing.T) {
	var buf bytes.Buffer
	lg := NewLogger(&buf, []string{"Authorization", "Cookie"})
	h := lg.Handler(okHandler)

	for i := 0; i < 3; i++ {
		r := newRequest("198.51.100.9")
		r.Header.Set("Authorization", "Bearer super-secret-token")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 log lines, got %d", len(lines))
	}
	if strings.Contains(buf.String(), "super-secret-token") {
		t.Fatal("secret token leaked into logs")
	}

	var prev string
	for i, line := range lines {
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if e.Headers["Authorization"] != "[REDACTED]" {
			t.Errorf("line %d: Authorization not redacted: %v", i, e.Headers)
		}
		if e.ChainHash == "" {
			t.Errorf("line %d: missing chain hash", i)
		}
		if e.ChainHash == prev {
			t.Errorf("line %d: chain hash did not advance", i)
		}
		if e.Status != http.StatusOK {
			t.Errorf("line %d: status = %d, want 200", i, e.Status)
		}
		prev = e.ChainHash
	}
}

// BenchmarkRateLimiter measures the per-request cost of the rate-limiter hot
// path under concurrent load. A 1ns window keeps the per-IP window at size ~1
// (prior timestamps are always expired), so this isolates the prune+append
// lock cost rather than measuring unbounded slice growth.
func BenchmarkRateLimiter(b *testing.B) {
	rl := NewRateLimiter(true, 1, 0, time.Nanosecond, NewWhitelist(nil))
	h := rl.Handler(okHandler)
	req := newRequest("10.10.10.10")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			h.ServeHTTP(httptest.NewRecorder(), req)
		}
	})
}
