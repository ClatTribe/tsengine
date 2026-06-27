package osint

import (
	"testing"
	"time"
)

func TestAssess_SubdomainTakeover(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	s := Snapshot{
		Org: "acme",
		DanglingRecords: []DanglingDNS{
			{Subdomain: "blog.acme.com", Record: "acme.github.io", Service: "github-pages", Claimable: true, Source: "subjack"},
			{Subdomain: "live.acme.com", Record: "acme.s3.amazonaws.com", Service: "s3", Claimable: false}, // still owned → not a takeover
		},
	}
	var hits []string
	var sev string
	for _, f := range Assess(s, Options{Now: now}) {
		if f.RuleID == "osint::subdomain-takeover" {
			hits = append(hits, f.Endpoint)
			sev = string(f.Severity)
			if f.Compliance.SOC2 == nil {
				t.Errorf("takeover finding for %s missing compliance", f.Endpoint)
			}
		}
	}
	if len(hits) != 1 || hits[0] != "blog.acme.com" {
		t.Fatalf("expected exactly the claimable record flagged, got %v", hits)
	}
	if sev != "high" {
		t.Errorf("subdomain takeover should be high severity, got %q", sev)
	}
}

// A clean footprint (no dangling/claimable records) yields no takeover finding (grounded — not noise).
func TestAssess_NoTakeoverWhenNotClaimable(t *testing.T) {
	s := Snapshot{Org: "secure", DanglingRecords: []DanglingDNS{
		{Subdomain: "ok.secure.com", Record: "secure.github.io", Service: "github-pages", Claimable: false},
	}}
	for _, f := range Assess(s, Options{}) {
		if f.RuleID == "osint::subdomain-takeover" {
			t.Errorf("a non-claimable record must not flag a takeover (got %s)", f.Endpoint)
		}
	}
}
