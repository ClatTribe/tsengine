package platformapi

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/operate"
)

// isPublicIP is the SSRF allowlist shared by /v1/assess, the badge, tlsscan, and osint — it must reject
// the special-use ranges the stdlib predicates miss (CGNAT, TEST-NETs, NAT64/6to4) while still allowing
// genuinely-routable public addresses, including IPv4-mapped IPv6.
func TestIsPublicIP_SpecialUseRanges(t *testing.T) {
	blocked := []string{
		"100.64.0.1",      // CGNAT (RFC 6598) — the headline gap
		"100.127.255.255", // CGNAT upper edge
		"0.1.2.3",         // 0.0.0.0/8
		"192.0.0.1",       // IETF protocol assignments
		"192.0.2.5",       // TEST-NET-1
		"198.18.0.9",      // benchmarking
		"198.51.100.7",    // TEST-NET-2
		"203.0.113.10",    // TEST-NET-3
		"240.0.0.1",       // class E
		"::ffff:100.64.0.1", // CGNAT via IPv4-mapped IPv6 (must still be caught)
		"64:ff9b::8.8.8.8",  // NAT64-embedded IPv4
		"2002:0808:0808::",  // 6to4-embedded IPv4
		"2001:db8::1",       // documentation
		"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", // sanity: stdlib-covered still blocked
	}
	for _, s := range blocked {
		if isPublicIP(net.ParseIP(s)) {
			t.Errorf("isPublicIP(%s) = true, want false (SSRF guard must refuse it)", s)
		}
	}
	allowed := []string{
		"8.8.8.8", "1.1.1.1", "203.0.114.1", // 203.0.114/x is NOT the TEST-NET (113) — must stay allowed
		"2606:4700:4700::1111",  // public IPv6 (Cloudflare)
		"::ffff:8.8.8.8",        // public IPv4-mapped IPv6 must stay allowed
	}
	for _, s := range allowed {
		if !isPublicIP(net.ParseIP(s)) {
			t.Errorf("isPublicIP(%s) = false, want true (a routable public address)", s)
		}
	}
}

func hardenedWeb() webPosture {
	return webPosture{
		Reachable: true, RedirectsToHTTPS: true, TLSVersion: tls.VersionTLS13,
		Headers: http.Header{
			"Strict-Transport-Security": {"max-age=63072000; includeSubDomains"},
			"Content-Security-Policy":   {"default-src 'self'"},
			"X-Frame-Options":           {"DENY"},
			"X-Content-Type-Options":    {"nosniff"},
		},
		SecurityTxt: true,
	}
}

func TestAssessWeb_HardenedAllPass(t *testing.T) {
	checks, findings, penalty := assessWeb(hardenedWeb())
	if len(checks) != 5 {
		t.Fatalf("want 5 web checks, got %d", len(checks))
	}
	for _, c := range checks {
		if !c.OK {
			t.Errorf("hardened site should pass %q", c.Name)
		}
	}
	if len(findings) != 0 || penalty != 0 {
		t.Errorf("hardened site → no findings/penalty, got %d findings, penalty %d", len(findings), penalty)
	}
}

func TestAssessWeb_BareSiteFailsAll(t *testing.T) {
	checks, findings, penalty := assessWeb(webPosture{Reachable: true}) // no TLS, no headers, no security.txt
	for _, c := range checks {
		if c.OK {
			t.Errorf("bare site should fail %q", c.Name)
		}
	}
	// 1 high (no HTTPS = 30) + 4 low (5 each = 20) = 50
	if penalty != 50 {
		t.Errorf("bare site penalty want 50, got %d", penalty)
	}
	if len(findings) != 5 {
		t.Errorf("want 5 findings, got %d", len(findings))
	}
}

func TestAssessWeb_UnreachableOmitted(t *testing.T) {
	checks, findings, penalty := assessWeb(webPosture{Reachable: false})
	if checks != nil || findings != nil || penalty != 0 {
		t.Error("unreachable site must contribute no checks/findings/penalty (no false fails)")
	}
}

func TestAssess_CombinesEmailAndWeb(t *testing.T) {
	// Hardened email + hardened web → perfect score, grade A, 0 questionnaire failures (3+5 checks).
	a := assess(operate.DomainConfig{Name: "acme.com", DMARC: "reject", SPF: true, DKIM: true}, hardenedWeb())
	if a.Score != 100 || a.Grade != "A" {
		t.Errorf("hardened+hardened → 100/A, got %d/%s", a.Score, a.Grade)
	}
	if a.Questionnaire.Failed != 0 || a.Questionnaire.Total != 8 {
		t.Errorf("questionnaire want 0/8, got %d/%d", a.Questionnaire.Failed, a.Questionnaire.Total)
	}

	// Weak email (no DMARC) + bare web → lower score, multiple questionnaire failures.
	b := assess(operate.DomainConfig{Name: "weak.com"}, webPosture{Reachable: true})
	if b.Score >= a.Score {
		t.Errorf("weak+bare (%d) should score below hardened (%d)", b.Score, a.Score)
	}
	if b.Questionnaire.Failed < 5 {
		t.Errorf("weak+bare should fail many checks, got %d", b.Questionnaire.Failed)
	}
	if b.Questionnaire.Headline == "" {
		t.Error("questionnaire headline should be set")
	}
}

func TestSummarize_Headline(t *testing.T) {
	none := summarize([]assessCheck{{OK: true}, {OK: true}})
	if none.Failed != 0 || !strings.Contains(none.Headline, "pass") {
		t.Errorf("all-pass headline wrong: %+v", none)
	}
	some := summarize([]assessCheck{{OK: false}, {OK: true}, {OK: false}})
	if some.Failed != 2 || some.Total != 3 {
		t.Errorf("want 2/3, got %d/%d", some.Failed, some.Total)
	}
}
