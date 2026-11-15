package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// statusRecorder captures the status code and response size written downstream.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// LogEntry is one structured access-log record.
type LogEntry struct {
	Timestamp string            `json:"timestamp"`
	IP        string            `json:"ip"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Status    int               `json:"status"`
	LatencyMS float64           `json:"latency_ms"`
	Bytes     int               `json:"bytes"`
	Headers   map[string]string `json:"headers,omitempty"`
	ChainHash string            `json:"chain_hash"`
}

// Logger is middleware that emits one structured JSON log line per request.
// Sensitive headers are redacted, and each entry carries a hash chained from
// the previous entry so that deletion or tampering is detectable.
type Logger struct {
	out      io.Writer
	redact   map[string]struct{}
	mu       sync.Mutex
	prevHash string
	now      func() time.Time
}

// NewLogger returns a Logger writing JSON lines to out. redactHeaders lists
// request headers whose presence is logged as "[REDACTED]" (values never
// appear in the log).
func NewLogger(out io.Writer, redactHeaders []string) *Logger {
	redact := make(map[string]struct{}, len(redactHeaders))
	for _, h := range redactHeaders {
		redact[http.CanonicalHeaderKey(h)] = struct{}{}
	}
	return &Logger{out: out, redact: redact, now: time.Now}
}

// redactedHeaders returns, for each configured sensitive header present on the
// request, a "[REDACTED]" marker — proving the header was seen without leaking
// its value.
func (l *Logger) redactedHeaders(r *http.Request) map[string]string {
	var out map[string]string
	for key := range l.redact {
		if r.Header.Get(key) != "" {
			if out == nil {
				out = make(map[string]string)
			}
			out[key] = "[REDACTED]"
		}
	}
	return out
}

// write serializes and emits one entry, updating the hash chain. It is safe for
// concurrent use.
func (l *Logger) write(e LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Chain hash = sha256(prevHash || canonical-entry-without-hash).
	core, _ := json.Marshal(struct {
		Timestamp string            `json:"timestamp"`
		IP        string            `json:"ip"`
		Method    string            `json:"method"`
		Path      string            `json:"path"`
		Status    int               `json:"status"`
		LatencyMS float64           `json:"latency_ms"`
		Bytes     int               `json:"bytes"`
		Headers   map[string]string `json:"headers,omitempty"`
	}{e.Timestamp, e.IP, e.Method, e.Path, e.Status, e.LatencyMS, e.Bytes, e.Headers})

	sum := sha256.Sum256(append([]byte(l.prevHash), core...))
	e.ChainHash = hex.EncodeToString(sum[:])
	l.prevHash = e.ChainHash

	line, _ := json.Marshal(e)
	l.out.Write(append(line, '\n'))
}

// Handler wraps next, logging each request after it completes.
func (l *Logger) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := l.now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		l.write(LogEntry{
			Timestamp: start.UTC().Format(time.RFC3339Nano),
			IP:        ClientIP(r),
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    rec.status,
			LatencyMS: float64(l.now().Sub(start).Microseconds()) / 1000.0,
			Bytes:     rec.bytes,
			Headers:   l.redactedHeaders(r),
		})
	})
}
