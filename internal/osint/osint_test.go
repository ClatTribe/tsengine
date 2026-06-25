package osint

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestAssess_CleanFootprintYieldsNothing(t *testing.T) {
	// Grounded (§10): a clean external footprint — only in-scope hosts, no breaches/leaks, an
	// unregistered typosquat permutation — produces ZERO findings.
	out := Assess(Snapshot{
		Org:          "acme",
		ExposedHosts: []ExposedHost{{Host: "app.acme.com", InScope: true, Source: "crtsh"}},
		Typosquats:   []TyposquatDomain{{Domain: "acrne.com", Target: "acme.com", Registered: false, Source: "dnstwist"}},
	}, Options{})
	if len(out) != 0 {
		t.Fatalf("clean footprint should yield 0 findings, got %d: %+v", len(out), out)
	}
}

func TestAssess_RulesFireWithComplianceAndSeverity(t *testing.T) {
	out := Assess(Snapshot{
		Org:              "acme",
		BreachedAccounts: []BreachedAccount{{Email: "ceo@acme.com", Breach: "LinkedIn 2021", Classes: "passwords", Source: "hibp"}},
		LeakedSecrets:    []LeakedSecret{{Kind: "AWS access key", Location: "https://github.com/x/y", Source: "trufflehog", Verified: true}},
		ExposedHosts: []ExposedHost{
			{Host: "legacy.acme.com", Services: []string{"rdp"}, Source: "shodan"},  // risky → high
			{Host: "old.acme.com", Services: []string{"http"}, Source: "crtsh"},     // → medium
		},
		Typosquats: []TyposquatDomain{{Domain: "acme-login.com", Target: "acme.com", Registered: true, HasMX: true, Source: "dnstwist"}},
		Exposures:  []DataExposure{{What: "customer list", Location: "pastebin.com/x", Source: "spiderfoot"}},
		Advisories: []Advisory{{Title: "RCE in nginx", Component: "nginx", Severity: "high", Source: "taranis-ai"}},
	}, Options{})

	byRule := map[string]types.Finding{}
	for _, f := range out {
		byRule[f.RuleID] = f
		if f.Tool != "osint" {
			t.Errorf("%s: tool should be osint, got %q", f.RuleID, f.Tool)
		}
		if f.Compliance == nil {
			t.Errorf("%s: every OSINT finding must carry a compliance mapping", f.RuleID)
		}
		if len(f.RawOutput) == 0 {
			t.Errorf("%s: every finding must cite its OSINT source in raw_output", f.RuleID)
		}
	}
	for _, want := range []string{"osint::breached-credential", "osint::leaked-secret", "osint::exposed-host", "osint::typosquat-domain", "osint::data-exposure", "osint::advisory"} {
		if _, ok := byRule[want]; !ok {
			t.Errorf("expected a %s finding", want)
		}
	}
	// severity grounding
	if byRule["osint::leaked-secret"].Severity != types.SeverityCritical {
		t.Errorf("a validated leaked secret should be critical, got %s", byRule["osint::leaked-secret"].Severity)
	}
	if byRule["osint::breached-credential"].Severity != types.SeverityHigh {
		t.Errorf("a breached credential should be high, got %s", byRule["osint::breached-credential"].Severity)
	}
	// breach finding carries the GDPR breach-notification controls (the compliance enrichment)
	if !contains(byRule["osint::breached-credential"].Compliance.GDPR, "Art. 33") {
		t.Error("breached-credential should map to GDPR Art. 33 (breach notification)")
	}
	// advisory is an awareness signal → pattern_match, not verified (honest confidence)
	if byRule["osint::advisory"].VerificationStatus != types.VerificationPatternMatch {
		t.Errorf("advisory should be pattern_match (awareness), got %s", byRule["osint::advisory"].VerificationStatus)
	}
}

func TestAssess_ExposedHostRiskyServiceIsHigh(t *testing.T) {
	out := Assess(Snapshot{Org: "acme", ExposedHosts: []ExposedHost{{Host: "db.acme.com", Services: []string{"mysql"}, Source: "shodan"}}}, Options{})
	if len(out) != 1 || out[0].Severity != types.SeverityHigh {
		t.Fatalf("an exposed database service should be a single HIGH finding, got %+v", out)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
