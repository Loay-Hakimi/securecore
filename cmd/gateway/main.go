// Command gateway is the SecureCore secure API gateway entrypoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Loay-Hakimi/securecore/internal/config"
	"github.com/Loay-Hakimi/securecore/internal/gateway"
	"github.com/Loay-Hakimi/securecore/internal/middleware"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "1.0.0"

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("securecore %s\n", version)
		return
	}

	if err := run(*configPath); err != nil {
		log.Fatalf("[SecureCore] fatal: %v", err)
	}
}

func run(configPath string) error {
	// A missing config file is non-fatal: fall back to built-in defaults.
	path := configPath
	if _, err := os.Stat(path); err != nil {
		log.Printf("[SecureCore] config %q not found, using defaults", path)
		path = ""
	}

	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	// Resolve the log sink.
	logOut, closeLog, err := openLog(cfg.Logging.Output)
	if err != nil {
		return err
	}
	defer closeLog()

	proxy, err := gateway.NewReverseProxy(cfg.Upstream)
	if err != nil {
		return err
	}

	handler, comps := gateway.Build(cfg, proxy, logOut)

	// Background cleanup of idle rate-limit entries and expired bans.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cleanupWorker(ctx, cfg.RateLimiter.CleanupInterval.D(), comps)

	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(cfg.Server.Port),
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout.D(),
		WriteTimeout: cfg.Server.WriteTimeout.D(),
		IdleTimeout:  cfg.Server.IdleTimeout.D(),
	}

	printBanner(cfg, version)

	// Graceful shutdown on SIGINT/SIGTERM.
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-sig:
		log.Printf("[SecureCore] shutdown signal received")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// openLog resolves a logging.output value ("stdout", "stderr", or a file path).
func openLog(output string) (io.Writer, func(), error) {
	switch output {
	case "", "stdout":
		return os.Stdout, func() {}, nil
	case "stderr":
		return os.Stderr, func() {}, nil
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file: %w", err)
		}
		return f, func() { f.Close() }, nil
	}
}

func cleanupWorker(ctx context.Context, interval time.Duration, comps gateway.Components) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if comps.RateLimiter != nil {
				comps.RateLimiter.Store().Cleanup()
			}
			if comps.DDoSGuard != nil {
				comps.DDoSGuard.BanList().Cleanup()
			}
		}
	}
}

func printBanner(cfg config.Config, version string) {
	headerCount := len(middleware.NewSecurityHeaders(cfg.SecurityHeaders).Values())
	log.Printf("[SecureCore] 🌐 Secure API Gateway v%s", version)
	log.Printf("[+] Rate Limiter     : %s", onOff(cfg.RateLimiter.Enabled,
		fmt.Sprintf("%d req/min per IP, burst: %d", cfg.RateLimiter.RequestsPerMinute, cfg.RateLimiter.Burst)))
	log.Printf("[+] DDoS Protection  : %s", onOff(cfg.DDoSProtection.Enabled,
		fmt.Sprintf("%d global RPS ceiling", cfg.DDoSProtection.GlobalRPSCeiling)))
	log.Printf("[+] Security Headers : %d headers active", headerCount)
	log.Printf("[+] Secure Logging   : %s → %s", cfg.Logging.Format, cfg.Logging.Output)
	log.Printf("[+] Upstream         : %s", cfg.Upstream.URL)
	log.Printf("[✓] Gateway listening on :%d", cfg.Server.Port)
}

func onOff(enabled bool, detail string) string {
	if enabled {
		return "enabled (" + detail + ")"
	}
	return "disabled"
}
