package gateway

import (
	"io"
	"net/http"
	"time"

	"github.com/Loay-Hakimi/securecore/internal/config"
	"github.com/Loay-Hakimi/securecore/internal/middleware"
)

// Components holds the middleware instances the gateway is built from, so that
// background workers (e.g. cleanup) can reach their state.
type Components struct {
	RateLimiter *middleware.RateLimiter
	DDoSGuard   *middleware.DDoSGuard
	Headers     *middleware.SecurityHeaders
	Logger      *middleware.Logger
}

// Build assembles the full gateway handler and returns it together with the
// middleware components. The upstream handler is injectable so tests can
// substitute a mock backend.
//
// Request path (outer → inner):
//
//	Logger → DDoS Guard → Rate Limiter → Security Headers → [ /healthz | Reverse Proxy ]
//
// The logger is outermost so it records every request, including those
// rejected by the guard or limiter. Security headers are injected on the way
// back out, after the upstream response is assembled.
func Build(cfg config.Config, upstream http.Handler, logOut io.Writer) (http.Handler, Components) {
	whitelist := middleware.NewWhitelist(cfg.RateLimiter.Whitelist)

	rl := middleware.NewRateLimiter(
		cfg.RateLimiter.Enabled,
		cfg.RateLimiter.RequestsPerMinute,
		cfg.RateLimiter.Burst,
		time.Minute, // sliding window for "requests per minute"
		whitelist,
	)
	guard := middleware.NewDDoSGuard(
		cfg.DDoSProtection.Enabled,
		cfg.DDoSProtection.GlobalRPSCeiling,
		cfg.DDoSProtection.PerIPBanThreshold,
		cfg.DDoSProtection.BanWindow.D(),
		cfg.DDoSProtection.BanDuration.D(),
		cfg.DDoSProtection.EscalationMultiplier,
	)
	headers := middleware.NewSecurityHeaders(cfg.SecurityHeaders)
	logger := middleware.NewLogger(logOut, cfg.Logging.RedactHeaders)

	healthPath := cfg.Upstream.HealthCheck
	if healthPath == "" {
		healthPath = "/healthz"
	}

	mux := http.NewServeMux()
	mux.Handle(healthPath, HealthHandler())
	mux.Handle("/", upstream)

	// Compose inner → outer.
	var handler http.Handler = mux
	handler = headers.Handler(handler)
	handler = rl.Handler(handler)
	handler = guard.Handler(handler)
	handler = logger.Handler(handler)

	return handler, Components{RateLimiter: rl, DDoSGuard: guard, Headers: headers, Logger: logger}
}
