// Package middleware implements the SecureCore gateway's security middleware
// chain: DDoS guard, per-IP rate limiting, security-header injection and
// structured request logging.
package middleware

import (
	"net"
	"net/http"
)

// ClientIP extracts the client IP from a request's RemoteAddr. The gateway is
// intended to sit at the network edge, so RemoteAddr is trusted and
// X-Forwarded-For is deliberately NOT honored (it is client-spoofable).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Whitelist matches IPs against an allow-list of literal addresses and CIDR
// ranges. It is immutable after construction and safe for concurrent reads.
type Whitelist struct {
	ips  map[string]struct{}
	nets []*net.IPNet
}

// NewWhitelist builds a Whitelist from entries that may be literal IPs
// ("127.0.0.1") or CIDR blocks ("10.0.0.0/8"). Unparseable entries are skipped.
func NewWhitelist(entries []string) *Whitelist {
	w := &Whitelist{ips: make(map[string]struct{})}
	for _, e := range entries {
		if _, cidr, err := net.ParseCIDR(e); err == nil {
			w.nets = append(w.nets, cidr)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			w.ips[ip.String()] = struct{}{}
		}
	}
	return w
}

// Allowed reports whether ip is on the whitelist.
func (w *Whitelist) Allowed(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if _, ok := w.ips[parsed.String()]; ok {
		return true
	}
	for _, n := range w.nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
