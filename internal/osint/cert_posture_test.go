package osint

import (
	"testing"
	"time"
)

func TestAssess_CertPosture(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	s := Snapshot{
		Org:                 "acme",
		ExpectedCertIssuers: []string{"Let's Encrypt", "DigiCert"},
		Certificates: []CertObservation{
			// unexpected CA → cert-unexpected-issuer (high)
			{Domain: "acme.com", Issuer: "C=CN, O=Sketchy CA Ltd", Source: "crt.sh"},
			// expected CA, served, expired → cert-expired (high)
			{Domain: "old.acme.com", Issuer: "C=US, O=Let's Encrypt", NotAfter: "2026-06-01", Served: true},
			// expected CA, served, expiring within 21d → cert-expiring (medium)
			{Domain: "soon.acme.com", Issuer: "C=US, O=DigiCert Inc", NotAfter: "2026-07-10", Served: true},
			// expected CA, healthy expiry → no finding
			{Domain: "good.acme.com", Issuer: "C=US, O=Let's Encrypt", NotAfter: "2026-12-01", Served: true},
			// historical CT cert (not served), expired → must NOT flag expiry (CT history noise)
			{Domain: "hist.acme.com", Issuer: "C=US, O=Let's Encrypt", NotAfter: "2020-01-01", Served: false},
		},
	}
	got := map[string]string{} // rule -> endpoint
	for _, f := range Assess(s, Options{Now: now}) {
		if len(f.RuleID) >= 12 && f.RuleID[:12] == "osint::cert-" {
			got[f.RuleID] = f.Endpoint
		}
	}
	if got["osint::cert-unexpected-issuer"] != "acme.com" {
		t.Errorf("unexpected-issuer should fire for acme.com, got %v", got)
	}
	if got["osint::cert-expired"] != "old.acme.com" {
		t.Errorf("cert-expired should fire for old.acme.com, got %v", got)
	}
	if got["osint::cert-expiring"] != "soon.acme.com" {
		t.Errorf("cert-expiring should fire for soon.acme.com, got %v", got)
	}
	// good cert + historical-unserved cert must produce no cert findings for their domains
	for rule, ep := range got {
		if ep == "good.acme.com" || ep == "hist.acme.com" {
			t.Errorf("%s wrongly fired for a healthy/historical cert (%s)", rule, ep)
		}
	}
}

// With NO expected issuers, the unexpected-issuer check is skipped (can't ground "unexpected").
func TestAssess_CertNoExpectedIssuersSkipsUnexpected(t *testing.T) {
	s := Snapshot{Org: "x", Certificates: []CertObservation{{Domain: "x.com", Issuer: "Whoever CA"}}}
	for _, f := range Assess(s, Options{}) {
		if f.RuleID == "osint::cert-unexpected-issuer" {
			t.Error("must not flag unexpected-issuer without an expected-CA baseline")
		}
	}
}
