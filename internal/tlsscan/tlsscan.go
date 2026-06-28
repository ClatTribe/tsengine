// Package tlsscan is the host-side TLS/SSL posture core — the OWASP A02 "Cryptographic Failures" /
// PCI-DSS 4.2.1 coverage gap. Like internal/operate (identity), internal/osint (external exposure), and
// the checkdmarc email-auth reader, it is a grounded, LLM-free, snapshot-driven assessment: it performs a
// REAL TLS handshake and reports only what the handshake proves (§10) — a hardened endpoint yields zero
// findings. It reads authoritative protocol/cert state from Go's crypto/tls + crypto/x509 (not a signature
// corpus), so it is the assess-style posture sibling, NOT an in-house signature scanner (§13). Deep
// cipher-suite enumeration + TLS-vuln probing (Heartbleed/ROBOT/POODLE) remain the sandbox-tool job
// (testssl.sh / sslyze, registry tier) — the honest gated half, exactly like osint's keyed collectors.
//
// Findings carry the crypto CWEs (327/326/295) so the compliance.map hook maps them to SC-13/SC-8,
// PCI 4.2.1, HIPAA 164.312(e), SOC2 CC6.7 — the controls the crosswalk now covers.
package tlsscan

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// expiryWarn is how soon a not-yet-expired cert is flagged as expiring (renewal SLA window).
const expiryWarn = 21 * 24 * time.Hour

// dialTLS is the handshake seam (overridden in tests). It dials addr with cfg and returns the conn.
var dialTLS = func(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &tls.Dialer{Config: cfg, NetDialer: &net.Dialer{Timeout: 8 * time.Second}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

// Assess performs a TLS handshake against host (host[:port], default :443), resolving the host by name,
// and returns grounded posture findings. The caller is responsible for SSRF-screening host first (the
// handler does). For an SSRF-screened call that must NOT re-resolve (DNS-rebinding safety), use
// AssessPinned with the already-validated IP. A dial failure is an error, not a finding (we don't guess).
func Assess(ctx context.Context, host string) ([]types.Finding, error) {
	hostOnly, addr := normalize(host)
	if hostOnly == "" {
		return nil, fmt.Errorf("tlsscan: empty host")
	}
	return assess(ctx, hostOnly, addr)
}

// AssessPinned is the DNS-rebinding-safe entry point: it dials the caller-validated ip — closing the
// check-then-resolve TOCTOU where a rebinding name passes the SSRF screen then connects to an internal
// host — while still using the hostname for SNI + certificate validation. The handler uses this after
// tlsResolveAllowed returns the screened IP, mirroring assess_web.go's safeHTTPClient (resolve, then dial
// the resolved IP).
func AssessPinned(ctx context.Context, host string, ip net.IP) ([]types.Finding, error) {
	hostOnly, addr := normalize(host)
	if hostOnly == "" {
		return nil, fmt.Errorf("tlsscan: empty host")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		port = "443"
	}
	return assess(ctx, hostOnly, net.JoinHostPort(ip.String(), port))
}

// assess runs the handshake-based posture checks against dialAddr, using hostOnly for SNI + cert
// validation. dialAddr is a host:port (Assess) or a pinned ip:port (AssessPinned).
func assess(ctx context.Context, hostOnly, dialAddr string) ([]types.Finding, error) {
	// Handshake reading the cert even if untrusted, so we can assess an invalid cert rather than abort.
	conn, err := dialTLS(ctx, dialAddr, &tls.Config{InsecureSkipVerify: true, ServerName: hostOnly}) //nolint:gosec // posture read; validated manually below
	if err != nil {
		return nil, fmt.Errorf("tlsscan: handshake with %s failed: %w", dialAddr, err)
	}
	state := conn.ConnectionState()
	_ = conn.Close()

	var fs []types.Finding
	now := time.Now()

	// 1. Negotiated protocol version — TLS < 1.2 is the headline crypto failure (PCI forbids 1.0/1.1).
	if state.Version < tls.VersionTLS12 {
		fs = append(fs, mk(hostOnly, "tlsscan::legacy-protocol-negotiated", types.SeverityHigh, "CWE-327",
			"Server negotiated an outdated TLS version ("+verName(state.Version)+")",
			"The default handshake negotiated "+verName(state.Version)+". TLS 1.0/1.1 are deprecated and disallowed by PCI-DSS 4.2.1; require TLS 1.2 or higher."))
	}

	// 2. Certificate posture (expiry, weak key, trust, hostname).
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		switch {
		case now.After(leaf.NotAfter):
			fs = append(fs, mk(hostOnly, "tlsscan::cert-expired", types.SeverityHigh, "CWE-295",
				"TLS certificate has expired",
				"The certificate expired on "+leaf.NotAfter.UTC().Format("2006-01-02")+". Browsers and API clients will reject the connection."))
		case leaf.NotAfter.Sub(now) < expiryWarn:
			fs = append(fs, mk(hostOnly, "tlsscan::cert-expiring", types.SeverityMedium, "CWE-295",
				"TLS certificate expires soon",
				"The certificate expires on "+leaf.NotAfter.UTC().Format("2006-01-02")+" (under 21 days). Renew it to avoid an outage."))
		}
		if pk, ok := leaf.PublicKey.(*rsa.PublicKey); ok && pk.N.BitLen() < 2048 {
			fs = append(fs, mk(hostOnly, "tlsscan::weak-key", types.SeverityHigh, "CWE-326",
				fmt.Sprintf("TLS certificate uses a weak %d-bit RSA key", pk.N.BitLen()),
				"RSA keys below 2048 bits are considered breakable. Reissue the certificate with a 2048-bit (or larger) key, or an ECDSA key."))
		}
		// Trust: verify against the system roots. A self-signed / untrusted chain is a real issue for a
		// public-facing endpoint. (We don't pin DNSName here — hostname is checked separately below.)
		if _, verr := leaf.Verify(x509.VerifyOptions{Intermediates: intermediates(state.PeerCertificates)}); verr != nil {
			fs = append(fs, mk(hostOnly, "tlsscan::cert-untrusted", types.SeverityMedium, "CWE-295",
				"TLS certificate is not trusted by a public CA",
				"The chain did not validate against the system trust store ("+verr.Error()+"). A self-signed or unknown-CA certificate will be rejected by clients."))
		}
		// Hostname: skip for bare IP literals (an IP endpoint legitimately may not carry a DNS SAN).
		if net.ParseIP(hostOnly) == nil {
			if herr := leaf.VerifyHostname(hostOnly); herr != nil {
				fs = append(fs, mk(hostOnly, "tlsscan::cert-hostname-mismatch", types.SeverityMedium, "CWE-295",
					"TLS certificate does not match the hostname",
					"The certificate is not valid for "+hostOnly+" ("+herr.Error()+")."))
			}
		}
	}

	// 3. Legacy-protocol SUPPORT probe — even if the default negotiated 1.2+, does the server still
	//    ACCEPT a 1.0/1.1 client? An attacker can downgrade if it does.
	if legacy, lerr := dialTLS(ctx, dialAddr, &tls.Config{InsecureSkipVerify: true, ServerName: hostOnly, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); lerr == nil { //nolint:gosec // intentional downgrade probe
		v := legacy.ConnectionState().Version
		_ = legacy.Close()
		if v <= tls.VersionTLS11 {
			fs = append(fs, mk(hostOnly, "tlsscan::legacy-protocol-supported", types.SeverityMedium, "CWE-326",
				"Server still accepts a legacy TLS version ("+verName(v)+")",
				"The server completed a handshake at "+verName(v)+". Disable TLS 1.0/1.1 to prevent protocol-downgrade attacks (PCI-DSS 4.2.1)."))
		}
	}

	return fs, nil
}

func intermediates(chain []*x509.Certificate) *x509.CertPool {
	if len(chain) <= 1 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, c := range chain[1:] {
		pool.AddCert(c)
	}
	return pool
}

// normalize splits host[:port] → (hostOnly, host:port-with-default-443).
func normalize(host string) (string, string) {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")
	if host == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		return h, net.JoinHostPort(h, p)
	}
	return host, net.JoinHostPort(host, "443")
}

func verName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionSSL30: //nolint:staticcheck // naming the legacy version in a finding
		return "SSL 3.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

func mk(host, rule string, sev types.Severity, cwe, title, desc string) types.Finding {
	return types.Finding{
		RuleID:             rule,
		Tool:               "tlsscan",
		Severity:           sev,
		CWE:                []string{cwe},
		Endpoint:           "https://" + host,
		Title:              title,
		Description:        desc,
		MITRETechniques:    []string{"T1040", "T1557"}, // network sniffing / adversary-in-the-middle
		VerificationStatus: types.VerificationPatternMatch,
		DiscoveredAt:       time.Now().UTC(),
	}
}
