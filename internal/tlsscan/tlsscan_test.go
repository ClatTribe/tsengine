package tlsscan

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// httptest's TLS server uses a self-signed cert (untrusted) but a modern TLS 1.2+/strong-key config.
// So Assess must emit EXACTLY the untrusted finding and NOT fabricate a legacy-protocol / weak-key /
// expired finding — the grounding guard (a modern-but-self-signed endpoint yields only the real issue).
func TestAssess_SelfSignedServer_OnlyUntrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://") // 127.0.0.1:port

	fs, err := Assess(context.Background(), addr)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	rules := map[string]bool{}
	for _, f := range fs {
		rules[f.RuleID] = true
		if f.Tool != "tlsscan" || len(f.CWE) == 0 {
			t.Errorf("finding missing tool/CWE: %+v", f)
		}
	}
	if !rules["tlsscan::cert-untrusted"] {
		t.Errorf("self-signed cert should yield cert-untrusted, got rules %v", rules)
	}
	// Grounding: no false positives on the modern parts of httptest's config.
	for _, bad := range []string{"tlsscan::legacy-protocol-negotiated", "tlsscan::legacy-protocol-supported", "tlsscan::weak-key", "tlsscan::cert-expired"} {
		if rules[bad] {
			t.Errorf("false positive: httptest is modern TLS, must not emit %s", bad)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string][2]string{
		"example.com":          {"example.com", "example.com:443"},
		"https://example.com/": {"example.com", "example.com:443"},
		"example.com:8443":     {"example.com", "example.com:8443"},
		"127.0.0.1:9000":       {"127.0.0.1", "127.0.0.1:9000"},
	}
	for in, want := range cases {
		h, a := normalize(in)
		if h != want[0] || a != want[1] {
			t.Errorf("normalize(%q) = (%q,%q), want (%q,%q)", in, h, a, want[0], want[1])
		}
	}
}

// AssessPinned must dial the caller-validated IP (closing the DNS-rebinding TOCTOU) while keeping the
// hostname as SNI for certificate validation — it must NOT hand the re-resolvable hostname to the dialer.
func TestAssessPinned_DialsValidatedIPNotHostname(t *testing.T) {
	orig := dialTLS
	defer func() { dialTLS = orig }()
	var gotAddr, gotSNI string
	dialTLS = func(_ context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
		gotAddr, gotSNI = addr, cfg.ServerName
		return nil, errors.New("stub: no real handshake") // capture only; abort before any I/O
	}
	_, _ = AssessPinned(context.Background(), "evil.example:8443", net.ParseIP("203.0.113.7"))
	if gotAddr != "203.0.113.7:8443" {
		t.Errorf("AssessPinned must dial the pinned IP:port, got %q", gotAddr)
	}
	if gotSNI != "evil.example" {
		t.Errorf("SNI/ServerName must remain the hostname for cert validation, got %q", gotSNI)
	}
}

func TestAssess_DialFailureIsError(t *testing.T) {
	// An unroutable port → error, not a fabricated finding (we don't guess).
	if _, err := Assess(context.Background(), "127.0.0.1:1"); err == nil {
		t.Error("a failed handshake should return an error, not nil")
	}
}
