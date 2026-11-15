// Command bench measures SecureCore's real throughput, latency and memory on
// the current machine. It stands up a mock upstream and the full gateway in
// process, drives load through a loopback HTTP client, and prints a Markdown
// table. The numbers in the README are produced by running this command.
//
// Usage:
//
//	go run ./cmd/bench -duration 5s -concurrency 50
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Loay-Hakimi/securecore/internal/config"
	"github.com/Loay-Hakimi/securecore/internal/gateway"
)

func main() {
	duration := flag.Duration("duration", 5*time.Second, "load test duration")
	concurrency := flag.Int("concurrency", 50, "number of concurrent client workers")
	flag.Parse()

	// Mock upstream: returns 200 immediately.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	// Gateway with rate limiting / DDoS guard disabled to measure raw proxy
	// throughput (matching the "no rate limit" row in the README).
	cfg := config.Default()
	cfg.Upstream.URL = upstream.URL
	cfg.RateLimiter.Enabled = false
	cfg.DDoSProtection.Enabled = false

	proxy, err := gateway.NewReverseProxy(cfg.Upstream)
	if err != nil {
		fmt.Fprintln(os.Stderr, "build proxy:", err)
		os.Exit(1)
	}
	handler, _ := gateway.Build(cfg, proxy, io.Discard)
	gw := httptest.NewServer(handler)
	defer gw.Close()

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        *concurrency * 2,
			MaxIdleConnsPerHost: *concurrency * 2,
		},
		Timeout: 10 * time.Second,
	}

	var (
		total    int64
		failures int64
		latMu    sync.Mutex
		lats     []time.Duration
		wg       sync.WaitGroup
	)
	deadline := time.Now().Add(*duration)

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 4096)
			for time.Now().Before(deadline) {
				start := time.Now()
				resp, err := client.Get(gw.URL + "/api/test")
				if err != nil {
					atomic.AddInt64(&failures, 1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				local = append(local, time.Since(start))
				if resp.StatusCode != http.StatusOK {
					atomic.AddInt64(&failures, 1)
				}
				atomic.AddInt64(&total, 1)
			}
			latMu.Lock()
			lats = append(lats, local...)
			latMu.Unlock()
		}()
	}
	wg.Wait()

	elapsed := time.Since(deadline.Add(-*duration))
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	throughput := float64(total) / elapsed.Seconds()

	fmt.Println("# SecureCore benchmark results")
	fmt.Println()
	fmt.Printf("- Date: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("- Host: %s/%s, %d logical CPUs, Go %s\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
	fmt.Printf("- Load: %d concurrent workers for %s, in-process loopback\n", *concurrency, *duration)
	fmt.Println()
	fmt.Println("| Metric | Result |")
	fmt.Println("|--------|--------|")
	fmt.Printf("| Requests completed | %d |\n", total)
	fmt.Printf("| Failures | %d |\n", failures)
	fmt.Printf("| Throughput | **~%.0f req/sec** |\n", throughput)
	fmt.Printf("| Latency P50 | %s |\n", pctile(lats, 50))
	fmt.Printf("| Latency P99 | %s |\n", pctile(lats, 99))
	fmt.Printf("| Heap in use after run | ~%.1f MB |\n", float64(mem.HeapAlloc)/(1024*1024))
	fmt.Printf("| Goroutines at finish | %d |\n", runtime.NumGoroutine())
}

func pctile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx].Round(time.Microsecond)
}
