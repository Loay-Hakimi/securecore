// Package gateway wires the reverse proxy and the middleware chain into a
// single http.Handler.
package gateway

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/Loay-Hakimi/securecore/internal/config"
)

// NewReverseProxy builds a reverse proxy to the configured upstream service.
func NewReverseProxy(cfg config.UpstreamConfig) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream url: %w", err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("upstream url %q must include scheme and host", cfg.URL)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	timeout := cfg.Timeout.D()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	proxy.Transport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "502 Bad Gateway: upstream unreachable", http.StatusBadGateway)
	}
	return proxy, nil
}

// HealthHandler reports gateway liveness without touching the upstream.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"securecore"}`))
	}
}
