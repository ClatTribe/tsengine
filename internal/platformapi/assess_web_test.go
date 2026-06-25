package platformapi

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/operate"
)

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
