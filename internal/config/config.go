// Package config loads and validates the SecureCore gateway configuration
// from a YAML file, applying sensible defaults for any omitted values.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from a YAML string such as
// "10s", "5m" or "1h". It lets the config file use human-readable durations.
type Duration time.Duration

// UnmarshalYAML parses a duration string into a Duration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// D returns the underlying time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Config is the full gateway configuration.
type Config struct {
	Server          ServerConfig          `yaml:"server"`
	Upstream        UpstreamConfig        `yaml:"upstream"`
	RateLimiter     RateLimiterConfig     `yaml:"rate_limiter"`
	DDoSProtection  DDoSConfig            `yaml:"ddos_protection"`
	SecurityHeaders SecurityHeadersConfig `yaml:"security_headers"`
	Logging         LoggingConfig         `yaml:"logging"`
}

// ServerConfig holds listener settings.
type ServerConfig struct {
	Port         int      `yaml:"port"`
	ReadTimeout  Duration `yaml:"read_timeout"`
	WriteTimeout Duration `yaml:"write_timeout"`
	IdleTimeout  Duration `yaml:"idle_timeout"`
}

// UpstreamConfig describes the backend service to proxy to.
type UpstreamConfig struct {
	URL         string   `yaml:"url"`
	HealthCheck string   `yaml:"health_check"`
	Timeout     Duration `yaml:"timeout"`
}

// RateLimiterConfig configures the per-IP sliding-window rate limiter.
type RateLimiterConfig struct {
	Enabled           bool     `yaml:"enabled"`
	RequestsPerMinute int      `yaml:"requests_per_minute"`
	Burst             int      `yaml:"burst"`
	CleanupInterval   Duration `yaml:"cleanup_interval"`
	Whitelist         []string `yaml:"whitelist"`
}

// DDoSConfig configures the DDoS guard.
type DDoSConfig struct {
	Enabled              bool     `yaml:"enabled"`
	GlobalRPSCeiling     int64    `yaml:"global_rps_ceiling"`
	PerIPBanThreshold    int      `yaml:"per_ip_ban_threshold"` // requests within BanWindow
	BanWindow            Duration `yaml:"ban_window"`
	BanDuration          Duration `yaml:"ban_duration"`
	EscalationMultiplier float64  `yaml:"escalation_multiplier"`
}

// SecurityHeadersConfig configures injected response headers.
type SecurityHeadersConfig struct {
	HSTSMaxAge        int    `yaml:"hsts_max_age"`
	CSP               string `yaml:"csp"`
	PermissionsPolicy string `yaml:"permissions_policy"`
	ReferrerPolicy    string `yaml:"referrer_policy"`
	FrameOptions      string `yaml:"frame_options"`
}

// LoggingConfig configures the structured logger.
type LoggingConfig struct {
	Level         string   `yaml:"level"`
	Format        string   `yaml:"format"`
	Output        string   `yaml:"output"`
	RedactHeaders []string `yaml:"redact_headers"`
}

// Default returns a Config populated with safe defaults.
func Default() Config {
	return Config{
		Server: ServerConfig{
			Port:         8080,
			ReadTimeout:  Duration(10 * time.Second),
			WriteTimeout: Duration(10 * time.Second),
			IdleTimeout:  Duration(60 * time.Second),
		},
		Upstream: UpstreamConfig{
			URL:         "http://localhost:3000",
			HealthCheck: "/healthz",
			Timeout:     Duration(5 * time.Second),
		},
		RateLimiter: RateLimiterConfig{
			Enabled:           true,
			RequestsPerMinute: 60,
			Burst:             10,
			CleanupInterval:   Duration(5 * time.Minute),
			Whitelist:         []string{"127.0.0.1"},
		},
		DDoSProtection: DDoSConfig{
			Enabled:              true,
			GlobalRPSCeiling:     5000,
			PerIPBanThreshold:    200,
			BanWindow:            Duration(10 * time.Second),
			BanDuration:          Duration(15 * time.Minute),
			EscalationMultiplier: 2.0,
		},
		SecurityHeaders: SecurityHeadersConfig{
			HSTSMaxAge:        63072000,
			CSP:               "default-src 'self'; script-src 'self'",
			PermissionsPolicy: "geolocation=(), microphone=(), camera=()",
			ReferrerPolicy:    "strict-origin-when-cross-origin",
			FrameOptions:      "DENY",
		},
		Logging: LoggingConfig{
			Level:         "info",
			Format:        "json",
			Output:        "stdout",
			RedactHeaders: []string{"Authorization", "Cookie", "X-API-Key"},
		},
	}
}

// Load reads a YAML config file, overlaying it on the defaults, then validates.
// If path is empty, the defaults are returned.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the configuration for obviously invalid values.
func (c Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port %d out of range 1-65535", c.Server.Port)
	}
	if c.Upstream.URL == "" {
		return fmt.Errorf("upstream.url must not be empty")
	}
	if c.RateLimiter.Enabled && c.RateLimiter.RequestsPerMinute <= 0 {
		return fmt.Errorf("rate_limiter.requests_per_minute must be > 0 when enabled")
	}
	if c.DDoSProtection.Enabled && c.DDoSProtection.PerIPBanThreshold <= 0 {
		return fmt.Errorf("ddos_protection.per_ip_ban_threshold must be > 0 when enabled")
	}
	if c.DDoSProtection.EscalationMultiplier < 1 {
		return fmt.Errorf("ddos_protection.escalation_multiplier must be >= 1")
	}
	return nil
}
