package middleware

import (
	"net/http"
	"strconv"

	"github.com/Loay-Hakimi/securecore/internal/config"
)

// SecurityHeaders injects the OWASP-recommended response header set on every
// response passing through the gateway.
type SecurityHeaders struct {
	headers map[string]string
}

// NewSecurityHeaders builds the injector from configuration.
func NewSecurityHeaders(cfg config.SecurityHeadersConfig) *SecurityHeaders {
	frame := cfg.FrameOptions
	if frame == "" {
		frame = "DENY"
	}
	referrer := cfg.ReferrerPolicy
	if referrer == "" {
		referrer = "strict-origin-when-cross-origin"
	}
	h := map[string]string{
		"Strict-Transport-Security": "max-age=" + strconv.Itoa(cfg.HSTSMaxAge) + "; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           frame,
		"Referrer-Policy":           referrer,
		"X-XSS-Protection":          "1; mode=block",
	}
	if cfg.CSP != "" {
		h["Content-Security-Policy"] = cfg.CSP
	}
	if cfg.PermissionsPolicy != "" {
		h["Permissions-Policy"] = cfg.PermissionsPolicy
	}
	return &SecurityHeaders{headers: h}
}

// Values returns a copy of the headers that will be injected.
func (s *SecurityHeaders) Values() map[string]string {
	out := make(map[string]string, len(s.headers))
	for k, v := range s.headers {
		out[k] = v
	}
	return out
}

// headerInjector wraps a ResponseWriter and sets the security headers just
// before the response status is written, so they take precedence over any
// headers copied from an upstream response.
type headerInjector struct {
	http.ResponseWriter
	headers map[string]string
	wrote   bool
}

func (h *headerInjector) inject() {
	if h.wrote {
		return
	}
	dst := h.ResponseWriter.Header()
	for k, v := range h.headers {
		if v != "" {
			dst.Set(k, v)
		}
	}
	h.wrote = true
}

func (h *headerInjector) WriteHeader(code int) {
	h.inject()
	h.ResponseWriter.WriteHeader(code)
}

func (h *headerInjector) Write(b []byte) (int, error) {
	if !h.wrote {
		h.inject()
	}
	return h.ResponseWriter.Write(b)
}

// Handler wraps next so that security headers are injected on its response.
func (s *SecurityHeaders) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&headerInjector{ResponseWriter: w, headers: s.headers}, r)
	})
}
