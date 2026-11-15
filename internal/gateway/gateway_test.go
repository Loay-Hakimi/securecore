package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Loay-Hakimi/securecore/internal/config"
)

func TestBuildProxiesToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "hit")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "hello from upstream")
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Upstream.URL = upstream.URL
	cfg.RateLimiter.Enabled = false
	cfg.DDoSProtection.Enabled = false

	proxy, err := NewReverseProxy(cfg.Upstream)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := Build(cfg, proxy, io.Discard)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	req.RemoteAddr = "203.0.113.1:5000"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "hello from upstream") {
		t.Fatalf("body not proxied: %q", rec.Body.String())
	}
	// Security headers injected on top of the upstream response.
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("security header not injected on proxied response")
	}
	if rec.Header().Get("X-Upstream") != "hit" {
		t.Errorf("upstream header not preserved")
	}
}

func TestHealthEndpointBypassesUpstream(t *testing.T) {
	cfg := config.Default()
	cfg.Upstream.URL = "http://127.0.0.1:1" // unreachable on purpose
	cfg.Upstream.HealthCheck = "/healthz"

	proxy, err := NewReverseProxy(cfg.Upstream)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := Build(cfg, proxy, io.Discard)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected health body: %q", rec.Body.String())
	}
}

func TestUpstreamErrorReturns502(t *testing.T) {
	cfg := config.Default()
	cfg.Upstream.URL = "http://127.0.0.1:1" // nothing listening
	cfg.RateLimiter.Enabled = false
	cfg.DDoSProtection.Enabled = false

	proxy, err := NewReverseProxy(cfg.Upstream)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := Build(cfg, proxy, io.Discard)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "203.0.113.2:5000"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestInvalidUpstreamURL(t *testing.T) {
	if _, err := NewReverseProxy(config.UpstreamConfig{URL: "://missing-scheme"}); err == nil {
		t.Fatal("expected error for invalid upstream url")
	}
}
