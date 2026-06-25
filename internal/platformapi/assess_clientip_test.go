package platformapi

import (
	"net"
	"net/http"
	"testing"
)

func mustCIDRs(t *testing.T, ss ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, s := range ss {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("bad cidr %q: %v", s, err)
		}
		out = append(out, n)
	}
	return out
}

func req(remoteAddr, xff string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientIP_NoTrustedProxy_UsesRemoteAddr(t *testing.T) {
	// No trusted proxies configured → forwarded headers are IGNORED (a client could forge them).
	var none []*net.IPNet
	if got := clientIPFrom(req("203.0.113.9:5000", "1.2.3.4"), none); got != "203.0.113.9" {
		t.Errorf("no trusted proxy: want RemoteAddr 203.0.113.9, got %q", got)
	}
}

func TestClientIP_UntrustedClientCannotSpoof(t *testing.T) {
	// The direct peer is NOT a trusted proxy → its X-Forwarded-For is ignored (anti-spoof / anti-poison).
	trusted := mustCIDRs(t, "10.0.0.0/8")
	if got := clientIPFrom(req("198.51.100.7:443", "9.9.9.9, 8.8.8.8"), trusted); got != "198.51.100.7" {
		t.Errorf("untrusted client must not spoof via XFF: want 198.51.100.7, got %q", got)
	}
}

func TestClientIP_TrustedProxy_UsesForwardedClient(t *testing.T) {
	// RemoteAddr is the trusted proxy → take the rightmost non-trusted XFF entry (the real client the
	// proxy appended). An attacker-prepended entry is to the LEFT and is therefore ignored.
	trusted := mustCIDRs(t, "10.0.0.0/8")
	cases := []struct{ xff, want string }{
		{"203.0.113.50", "203.0.113.50"},                  // Caddy appended the real client
		{"66.66.66.66, 203.0.113.50", "203.0.113.50"},     // attacker prepended 66.. ; real client is rightmost
		{"203.0.113.50, 10.0.0.5", "203.0.113.50"},        // a trusted hop trails → skip it, take the client
		{"203.0.113.50, 10.0.0.5, 10.1.2.3", "203.0.113.50"}, // two trusted hops → skip both
	}
	for _, c := range cases {
		if got := clientIPFrom(req("10.0.0.5:1234", c.xff), trusted); got != c.want {
			t.Errorf("trusted proxy XFF %q: want %q, got %q", c.xff, c.want, got)
		}
	}
}

func TestClientIP_TrustedProxy_NoXFF_FallsBackToProxy(t *testing.T) {
	trusted := mustCIDRs(t, "10.0.0.0/8")
	if got := clientIPFrom(req("10.0.0.5:1234", ""), trusted); got != "10.0.0.5" {
		t.Errorf("trusted proxy, no XFF: want the proxy IP 10.0.0.5, got %q", got)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	// CIDRs + bare IPs (→ /32 or /128) both parse; junk is dropped.
	p := parseTrustedProxies("10.0.0.0/8, 172.18.0.5, , garbage, 2001:db8::/32")
	if len(p) != 3 {
		t.Fatalf("want 3 parsed nets, got %d", len(p))
	}
	if !ipInCIDRs("172.18.0.5", p) || ipInCIDRs("172.18.0.6", p) {
		t.Errorf("bare IP should become a /32 host route")
	}
	if !ipInCIDRs("10.255.1.1", p) {
		t.Errorf("10.0.0.0/8 should contain 10.255.1.1")
	}
}
