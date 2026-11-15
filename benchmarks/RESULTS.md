# SecureCore benchmark results

All numbers below were produced on the machine listed, by running the
commands shown. Reproduce them with `make bench` (or the individual commands).
These are real measurements — not projections.

## Environment

- Date: 2026-11-15
- Host: windows/amd64, 8 logical CPUs
- Go: go1.27.4
- Method: mock upstream + full gateway, in-process over the loopback interface

## End-to-end load (`go run ./cmd/bench -duration 5s -concurrency 50`)

| Metric | Result |
|--------|--------|
| Requests completed | 37,388 |
| Failures | 0 |
| Throughput | ~7,500 req/sec |
| Latency P50 | 5.6 ms |
| Latency P99 | 27.9 ms |
| Heap in use after run | ~5.6 MB |

> Note: throughput here is bounded by the in-process loopback HTTP client and
> the Windows network stack, not by the gateway's internal logic. Treat it as a
> floor for this machine, not a hardware ceiling.

## Microbenchmarks (`go test -bench=. -benchmem`)

| Benchmark | ns/op | allocs/op |
|-----------|-------|-----------|
| `store.BenchmarkAllow` (rate-limit decision: lock + window prune + append) | 412 | 0 |
| `middleware.BenchmarkRateLimiter` (full limiter middleware pass, incl. recorder) | 1,739 | 16 |

## Binary

| Metric | Result |
|--------|--------|
| Stripped binary (`go build -ldflags "-s -w"`) | 7.6 MB (7,974,912 bytes) |

## Race detector

`go test -race ./...` requires CGO and a C compiler, which were not available on
this build machine. The concurrency test (`store.TestIPStoreConcurrent`) runs
without `-race` here; run `make race` in an environment with CGO to exercise the
detector.
