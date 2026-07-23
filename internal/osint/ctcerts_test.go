package osint

import (
	"context"
	"strings"
	"testing"
)

// a crt.sh response with two issuers (Let's Encrypt twice + an unexpected CA once).
const ctCertSample = `[
  {"name_value":"acme.com","common_name":"acme.com","issuer_name":"C=US, O=Let's Encrypt, CN=R3","not_after":"2030-01-01T00:00:00"},
  {"name_value":"www.acme.com","common_name":"www.acme.com","issuer_name":"C=US, O=Let's Encrypt, CN=R3","not_after":"2030-02-01T00:00:00"},
  {"name_value":"vpn.acme.com","common_name":"vpn.acme.com","issuer_name":"C=CN, O=WoSign CA","not_after":"2030-03-01T00:00:00"}
]`

func TestParseCTCerts_DedupsByIssuer(t *testing.T) {
	certs := ParseCTCerts("acme.com", []byte(ctCertSample))
	if len(certs) != 2 {
		t.Fatalf("want 2 distinct issuers, got %d: %+v", len(certs), certs)
	}
	for _, c := range certs {
		if c.Source != "crtsh" || c.Served {
			t.Errorf("crt.sh cert must be source=crtsh, Served=false (CT history): %+v", c)
		}
		if c.Domain != "acme.com" {
			t.Errorf("domain should be the queried apex: %q", c.Domain)
		}
	}
}

func TestParseCTCerts_Malformed(t *testing.T) {
	for _, b := range []string{"", "not json", "{}", "   "} {
		if c := ParseCTCerts("acme.com", []byte(b)); c != nil {
			t.Errorf("input %q must yield no certs", b)
		}
	}
	// rows without an issuer_name contribute nothing (grounded)
	if c := ParseCTCerts("acme.com", []byte(`[{"name_value":"acme.com","common_name":"acme.com"}]`)); c != nil {
		t.Errorf("a row with no issuer must yield no cert observation, got %v", c)
	}
}

// TestCollectCT_EmitsCertsAndUnexpectedIssuerFires: the same crt.sh fetch now yields cert observations,
// and with the tenant's known CAs declared, an unexpected-issuer cert produces a live finding.
func TestCollectCT_EmitsCertsAndUnexpectedIssuerFires(t *testing.T) {
	fetch := func(_ context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "acme.com") {
			return []byte(ctCertSample), nil
		}
		return nil, nil
	}
	snap := CollectCT(context.Background(), "Acme", []string{"acme.com"}, nil, fetch)
	if len(snap.Certificates) != 2 {
		t.Fatalf("CollectCT should surface 2 distinct-issuer certs, got %d", len(snap.Certificates))
	}
	// declare the org's known CA → the WoSign cert is unexpected → a live finding
	snap.ExpectedCertIssuers = []string{"Let's Encrypt"}
	var unexpected int
	for _, f := range Assess(snap, Options{}) {
		if strings.Contains(f.RuleID, "cert-unexpected-issuer") {
			unexpected++
		}
	}
	if unexpected != 1 {
		t.Errorf("exactly the WoSign cert must fire cert-unexpected-issuer, got %d", unexpected)
	}
}
