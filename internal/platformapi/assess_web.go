package platformapi

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// assess_web.go extends the public PLG assessment (assess.go) from email-auth-only into a
// "security-questionnaire readiness" scan. Every added check is still free + public-safe: one
// HTTPS GET to the homepage (headers + TLS), an http→https redirect probe, and a HEAD for
// security.txt. It is hardened against SSRF (refuses to connect to private/loopback IPs) and is
// best-effort: when a site can't be reached we OMIT the web checks rather than falsely failing them
// (the §10 grounding rule — never assert a fail we couldn't verify).

const assessUA = "TensorShield-Assess/1.0 (+https://tensorshield.ai/scan; read-only posture check)"

// webPosture is the read-only web observation. Reachable=false → contributes nothing.
type webPosture struct {
	Domain           string
	Reachable        bool
	RedirectsToHTTPS bool
	TLSVersion       uint16
	Headers          http.Header
	SecurityTxt      bool
}

func hasHeader(h http.Header, key string) bool { return strings.TrimSpace(h.Get(key)) != "" }

// assessWeb scores the web posture into questionnaire-readiness checks + teaser findings + a score
// penalty. Pure (no I/O), so it is deterministic + testable. Header penalties are LOW (a fast-moving
// small SaaS legitimately lacks some) so they nudge the grade without dominating; only "no HTTPS" is
// high. An unreachable site yields nothing.
func assessWeb(wp webPosture) (checks []assessCheck, findings []assessFinding, penalty int) {
	if !wp.Reachable {
		return nil, nil, 0
	}
	h := wp.Headers

	https := wp.RedirectsToHTTPS && wp.TLSVersion >= tls.VersionTLS12
	checks = append(checks, assessCheck{Name: "HTTPS enforced", OK: https,
		Detail: ternary(https, "Served over modern TLS with an HTTP→HTTPS redirect.",
			"HTTP isn't redirected to HTTPS, or TLS is older than 1.2 — traffic can be intercepted."),
		Fix: ifFail(!https, httpsFix())})
	if !https {
		findings = append(findings, assessFinding{Title: "HTTP not forced to HTTPS / weak TLS", Severity: "high"})
		penalty += severityPenalty(types.SeverityHigh)
	}

	hsts := hasHeader(h, "Strict-Transport-Security")
	checks = append(checks, assessCheck{Name: "HSTS", OK: hsts,
		Detail: ternary(hsts, "Strict-Transport-Security header present.", "No HSTS header — browsers will still try HTTP first."),
		Fix: ifFail(!hsts, hstsFix())})
	if !hsts {
		findings = append(findings, assessFinding{Title: "Missing HSTS header", Severity: "low"})
		penalty += severityPenalty(types.SeverityLow)
	}

	csp := hasHeader(h, "Content-Security-Policy")
	checks = append(checks, assessCheck{Name: "Content-Security-Policy", OK: csp,
		Detail: ternary(csp, "CSP header present.", "No Content-Security-Policy — weaker defense against XSS/injection."),
		Fix: ifFail(!csp, cspFix())})
	if !csp {
		findings = append(findings, assessFinding{Title: "Missing Content-Security-Policy", Severity: "low"})
		penalty += severityPenalty(types.SeverityLow)
	}

	// Clickjacking + MIME-sniffing: X-Frame-Options (or CSP frame-ancestors) AND X-Content-Type-Options.
	clickjack := hasHeader(h, "X-Frame-Options") || csp
	mime := hasHeader(h, "X-Content-Type-Options")
	prot := clickjack && mime
	checks = append(checks, assessCheck{Name: "Clickjacking & MIME protections", OK: prot,
		Detail: ternary(prot, "X-Frame-Options/frame-ancestors + X-Content-Type-Options set.",
			"Missing X-Frame-Options (or CSP frame-ancestors) and/or X-Content-Type-Options."),
		Fix: ifFail(!prot, clickjackFix())})
	if !prot {
		findings = append(findings, assessFinding{Title: "Missing clickjacking / MIME-sniffing protections", Severity: "low"})
		penalty += severityPenalty(types.SeverityLow)
	}

	checks = append(checks, assessCheck{Name: "Security contact (security.txt)", OK: wp.SecurityTxt,
		Detail: ternary(wp.SecurityTxt, "Publishes /.well-known/security.txt with a disclosure contact.",
			"No security.txt — enterprise questionnaires expect a documented security/vuln-disclosure contact."),
		Fix: ifFail(!wp.SecurityTxt, securityTxtFix(wp.Domain))})
	if !wp.SecurityTxt {
		findings = append(findings, assessFinding{Title: "No security.txt / vulnerability-disclosure contact", Severity: "low"})
		penalty += severityPenalty(types.SeverityLow)
	}
	return checks, findings, penalty
}

// summarize reframes the check set as the founder-facing questionnaire-readiness headline.
func summarize(checks []assessCheck) questionnaireSummary {
	failed := 0
	for _, c := range checks {
		if !c.OK {
			failed++
		}
	}
	qs := questionnaireSummary{Failed: failed, Total: len(checks)}
	switch failed {
	case 0:
		qs.Headline = "You pass the basic checks a typical enterprise security questionnaire asks about."
	case 1:
		qs.Headline = "You'd fail 1 of the basic checks a typical enterprise security questionnaire asks about."
	default:
		qs.Headline = fmt.Sprintf("You'd fail %d of the %d basic checks a typical enterprise security questionnaire asks about.", failed, len(checks))
	}
	return qs
}

// --- the read-only prober (real I/O; the scoring above is pure) ---

// isPublicIP reports whether an IP is a routable public address (the SSRF guard).
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

// safeHTTPClient returns an http.Client that refuses to connect to non-public IPs (SSRF guard:
// resolves the host, rejects if ANY address is private, then dials the resolved public IP so there
// is no rebind window), caps redirects, and bounds every phase by timeout.
func safeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("resolve %s: %w", host, err)
			}
			for _, ip := range ips {
				if !isPublicIP(ip.IP) {
					return nil, fmt.Errorf("refusing to connect to non-public address for %s", host)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		// Accept older TLS so we can OBSERVE+report it (cert verification stays on).
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// probeWeb fetches the homepage (headers + TLS), checks the http→https redirect, and HEADs
// security.txt. Best-effort: any failure on the homepage → Reachable=false (web checks omitted).
func probeWeb(ctx context.Context, domain string) webPosture {
	client := safeHTTPClient(4 * time.Second)
	wp := webPosture{Domain: domain}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return wp
	}
	req.Header.Set("User-Agent", assessUA)
	resp, err := client.Do(req)
	if err != nil {
		return wp
	}
	wp.Reachable = true
	wp.Headers = resp.Header
	if resp.TLS != nil {
		wp.TLSVersion = resp.TLS.Version
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	wp.RedirectsToHTTPS = redirectsToHTTPS(ctx, domain)
	wp.SecurityTxt = headOK(ctx, client, "https://"+domain+"/.well-known/security.txt")
	return wp
}

// redirectsToHTTPS does a single non-following GET to the http:// origin and reports whether it
// 30x-redirects to an https:// Location.
func redirectsToHTTPS(ctx context.Context, domain string) bool {
	client := safeHTTPClient(4 * time.Second)
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", assessUA)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return strings.HasPrefix(strings.ToLower(resp.Header.Get("Location")), "https://")
	}
	return false
}

func headOK(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", assessUA)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 400
}
