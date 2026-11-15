package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
}

func TestLoadOverlaysDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
server:
  port: 9090
  read_timeout: 15s
upstream:
  url: "http://localhost:4000"
rate_limiter:
  requests_per_minute: 120
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.ReadTimeout.D() != 15*time.Second {
		t.Errorf("read_timeout = %v, want 15s", cfg.Server.ReadTimeout.D())
	}
	if cfg.RateLimiter.RequestsPerMinute != 120 {
		t.Errorf("rpm = %d, want 120", cfg.RateLimiter.RequestsPerMinute)
	}
	// Unset field keeps its default.
	if cfg.Server.WriteTimeout.D() != 10*time.Second {
		t.Errorf("write_timeout default lost: %v", cfg.Server.WriteTimeout.D())
	}
}

func TestLoadEmptyPathReturnsDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
	}
}

func TestValidateRejectsBadPort(t *testing.T) {
	c := Default()
	c.Server.Port = 70000
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

func TestValidateRejectsEmptyUpstream(t *testing.T) {
	c := Default()
	c.Upstream.URL = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for empty upstream url")
	}
}

func TestInvalidDurationErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("server:\n  read_timeout: \"not-a-duration\"\n"), 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("expected parse error for invalid duration")
	}
}
