<div align="center">

# 🌐 SecureCore
### High-Performance Secure API Gateway in Go

[![CI](https://github.com/Loay-Hakimi/securecore/actions/workflows/ci.yml/badge.svg)](https://github.com/Loay-Hakimi/securecore/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Focus-API%20Security-EF4444?style=for-the-badge&logo=shield&logoColor=white)](https://github.com)
[![Performance](https://img.shields.io/badge/Concurrency-Goroutines-00ADD8?style=for-the-badge)](https://github.com)
[![Status](https://img.shields.io/badge/Status-Active-22C55E?style=for-the-badge)](https://github.com)

> A production-grade **Secure API Gateway** built in Go — engineered to act as the first line of defense for backend services. Combines high-throughput concurrency via Goroutines, DDoS/rate-limit protection with Mutex-safe counters, strict security header injection, and structured secure logging into a single lightweight binary.

---

[Why Go](#-why-go-for-security) · [Features](#-features) · [Architecture](#-system-architecture) · [Installation](#-installation) · [Usage](#-usage) · [Benchmarks](#-performance-benchmarks)

</div>

---

## 🎯 Overview

**SecureCore** is a reverse-proxy API gateway that sits between the public internet and your backend services. It enforces security policies at the edge — before a single request reaches your application logic.

| Layer | Responsibility |
|-------|---------------|
| 🚦 **Rate Limiter** | Per-IP request throttling with sliding window algorithm |
| 🛡️ **DDoS Protection** | Goroutine-based concurrent request analysis & blocking |
| 🔒 **Security Headers** | Automatic injection of OWASP-recommended HTTP headers |
| 📝 **Secure Logging** | Structured, tamper-evident request/response audit trail |
| 🔄 **Reverse Proxy** | Transparent forwarding to upstream services |

---

## ⚡ Why Go for Security?

Go is not the obvious choice for API gateways — it is the *correct* choice. Here is why SecureCore is built in Go and not Python, Node.js, or Java:

### Concurrency Without Complexity
Go's **Goroutines** are OS-thread-multiplexed lightweight execution units. SecureCore spins a new Goroutine per incoming connection — handling thousands of simultaneous requests with a memory footprint that would be impossible in thread-per-request models.

```
Traditional server (1 thread per request):
  1,000 requests → 1,000 OS threads → ~8GB RAM

SecureCore (Goroutine per request):
  1,000 requests → 1,000 Goroutines → ~8MB RAM
```

### Mutex-Safe Shared State
Rate limiting requires shared mutable state — a classic race condition target. SecureCore uses Go's `sync.RWMutex` to protect IP counters with minimal lock contention:
- **Read lock** for counter lookups (non-blocking for concurrent reads)
- **Write lock** only on counter increments and expiry cleanups
- Zero data races — verified with Go's built-in `-race` detector

### Compiled Binary, Minimal Attack Surface
Go compiles to a single static binary with no runtime dependencies. No interpreter, no VM, no package manager at runtime — a dramatically reduced attack surface compared to interpreted language stacks.

---

## ✨ Features

### 🚦 Adaptive Rate Limiter
- Per-IP sliding window rate limiting with configurable thresholds
- Goroutine-safe counter management via `sync.RWMutex`
- Automatic IP expiry and memory cleanup via background Goroutine
- Returns `429 Too Many Requests` with `Retry-After` header on violation
- Whitelist support for trusted IPs (internal services, monitoring agents)

### 🛡️ DDoS Protection Layer
- Concurrent request pattern analysis across active connections
- Global request-per-second ceiling with atomic counters
- Automatic temporary IP banning on threshold breach
- Configurable ban duration and escalation multiplier for repeat offenders

### 🔒 Security Headers Injection
Automatically injects the full OWASP-recommended header set on every proxied response:

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | Force HTTPS |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Clickjacking protection |
| `Content-Security-Policy` | Configurable | XSS mitigation |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Data leakage control |
| `Permissions-Policy` | Configurable | Browser feature control |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter |

### 📝 Secure Logging System
- Structured JSON logs for every request: timestamp, IP, method, path, status, latency
- Sensitive data redaction — Authorization headers and cookies never appear in logs
- Log rotation with configurable max size and retention period
- Audit trail integrity: each log entry includes a chained hash for tamper detection

### 🔄 Reverse Proxy Core
- Transparent HTTP/HTTPS proxying to upstream services
- Connection pooling for upstream keep-alive efficiency
- Configurable timeout per upstream (connect, read, write)
- Health check endpoint for load balancer integration

---

## 🏗️ System Architecture

```
securecore/
│
├── cmd/
│   ├── gateway/
│   │   └── main.go             # Entrypoint: config load, server bootstrap, graceful shutdown
│   └── bench/
│       └── main.go             # Reproducible benchmark harness (see benchmarks/)
│
├── internal/
│   ├── gateway/
│   │   ├── proxy.go            # Reverse proxy core (httputil.ReverseProxy) + health handler
│   │   └── router.go           # Middleware chain assembly
│   │
│   ├── middleware/
│   │   ├── clientip.go         # Client-IP extraction + CIDR-aware whitelist
│   │   ├── ratelimiter.go      # Per-IP sliding-window rate limiter
│   │   ├── ddos_guard.go       # Global RPS ceiling + per-IP ban engine (escalating)
│   │   ├── headers.go          # Security header injection middleware
│   │   └── logger.go           # Structured logging w/ redaction + chained hash
│   │
│   ├── config/
│   │   └── config.go           # YAML config loader with defaults + validation
│   │
│   └── store/
│       ├── ip_store.go         # Sliding-window IP counter store (RWMutex-protected)
│       └── ban_list.go         # Temporary ban registry with TTL + escalation
│
├── benchmarks/
│   └── RESULTS.md              # Latest measured benchmark output
│
├── config.yaml                 # Gateway configuration
├── Dockerfile                  # Multi-stage build → scratch image
├── go.mod
├── go.sum
└── Makefile
```

### 🔄 Request Lifecycle

```
  [ Incoming Request ]
         │
         ▼
  ┌─────────────────┐
  │  DDoS Guard     │  ← Global RPS ceiling check
  └────────┬────────┘
           │ pass
           ▼
  ┌─────────────────┐
  │  Rate Limiter   │  ← Per-IP sliding window check
  └────────┬────────┘
           │ pass
           ▼
  ┌─────────────────┐
  │  Secure Logger  │  ← Log request metadata (sanitized)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │  Reverse Proxy  │  ← Forward to upstream service
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ Header Injector │  ← Inject security headers on response
  └────────┬────────┘
           │
           ▼
  [ Response to Client ]
```

---

## 🚀 Installation

### Prerequisites

- Go `1.22+`
- Make (optional, for Makefile shortcuts)

```bash
# Verify Go installation
go version
```

### Clone & Build

```bash
git clone https://github.com/Loay-Hakimi/securecore.git
cd securecore

# Download dependencies
go mod tidy

# Build binary
go build -o securecore ./cmd/gateway/

# Or using Make
make build
```

### Run with Race Detector (Development)

```bash
go run -race ./cmd/gateway/
```

---

## ⚙️ Configuration

```yaml
# config.yaml

server:
  port: 8080
  read_timeout: 10s
  write_timeout: 10s
  idle_timeout: 60s

upstream:
  url: "http://localhost:3000"
  health_check: "/health"
  timeout: 5s

rate_limiter:
  enabled: true
  requests_per_minute: 60
  burst: 10
  cleanup_interval: 5m
  whitelist:
    - "127.0.0.1"
    - "10.0.0.0/8"

ddos_protection:
  enabled: true
  global_rps_ceiling: 5000
  per_ip_ban_threshold: 200      # requests/10s triggers ban
  ban_duration: 15m
  escalation_multiplier: 2.0     # each repeat offense doubles ban duration

security_headers:
  hsts_max_age: 63072000
  csp: "default-src 'self'; script-src 'self'"
  permissions_policy: "geolocation=(), microphone=(), camera=()"

logging:
  level: "info"
  format: "json"
  output: "./logs/gateway.log"
  max_size_mb: 100
  max_backups: 7
  redact_headers:
    - "Authorization"
    - "Cookie"
    - "X-API-Key"
```

---

## 🖥️ Usage

### Start the Gateway

```bash
./securecore --config config.yaml
```

```
[SecureCore] 🌐 Secure API Gateway v1.0.0
[+] Rate Limiter     : enabled (60 req/min per IP, burst: 10)
[+] DDoS Protection  : enabled (5000 global RPS ceiling)
[+] Security Headers : 7 headers active
[+] Secure Logging   : JSON → ./logs/gateway.log
[+] Upstream         : http://localhost:3000
[✓] Gateway listening on :8080
```

### Test Rate Limiting

```bash
# Fire 100 rapid requests and observe 429 responses
for i in $(seq 1 100); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/test; done
```

### Inspect Security Headers

```bash
curl -I http://localhost:8080/api/test
```

```
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; script-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
X-XSS-Protection: 1; mode=block
```

### Docker Deployment

```bash
docker build -t securecore .
docker run -p 8080:8080 -v $(pwd)/config.yaml:/app/config.yaml securecore
```

---

## 📊 Performance Benchmarks

All numbers below are **real measurements** produced by the benchmark tooling in
this repo — not projections. Reproduce them with `make bench`. Full output is
saved in [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md).

Measured on: **windows/amd64, 8 logical CPUs, Go 1.27.4** — mock upstream + full
gateway, in-process over the loopback interface.

### End-to-end load — `go run ./cmd/bench -duration 5s -concurrency 50`

| Metric | Result |
|--------|--------|
| Throughput | **~7,500 req/sec** |
| Latency P50 | **5.6 ms** |
| Latency P99 | **27.9 ms** |
| Failures | **0** / 37,388 requests |
| Heap in use after run | **~5.6 MB** |
| Stripped binary size | **7.6 MB** (static, no runtime dependencies) |

> Throughput here is bounded by the in-process loopback HTTP client and the
> Windows network stack, not by the gateway's internal logic — treat it as a
> floor for this machine, not a hardware ceiling.

### Microbenchmarks — `go test -bench=. -benchmem`

| Benchmark | ns/op | allocs/op |
|-----------|-------|-----------|
| Rate-limit decision (`store.Allow`: lock + window prune + append) | **412** | **0** |
| Full rate-limiter middleware pass (incl. response recorder) | **1,739** | **16** |

> **Race detector:** `go test -race ./...` requires CGO and a C compiler, which
> were not available on the Windows build machine above. It instead runs in
> **GitHub Actions CI** (Ubuntu, CGO available) on every push — the
> `TestIPStoreConcurrent` test hammers the `RWMutex`-protected store with 50
> goroutines, and the suite passes race-free there (see the CI badge). Run
> `make race` locally where CGO is available to exercise the detector directly.

---

## 🔬 Security Testing

```bash
# Verify zero race conditions under concurrent load
go test -race ./...

# Run all unit tests
go test ./...

# Benchmark the rate limiter under contention
go test -bench=BenchmarkRateLimiter -benchmem ./internal/middleware/
```

---

## 🗺️ Roadmap

- [ ] JWT validation middleware
- [ ] mTLS support for upstream connections
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Redis-backed distributed rate limiting for multi-instance deployments
- [ ] gRPC proxying support
- [ ] Web UI dashboard for live traffic monitoring

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with ⚡ **Go** for teams who can't afford downtime

**[⭐ Star this repo](https://github.com/Loay-Hakimi/securecore)** · **[View Portfolio](https://github.com/Loay-Hakimi)**

</div>
