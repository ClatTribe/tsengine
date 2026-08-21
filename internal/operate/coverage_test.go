package operate

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// THE BUG THIS EXISTS FOR. A tenant with no risky OAuth apps and a tenant whose grant read
// was never permitted both arrive with OAuthGrants empty — and the second reads, on the
// customer's screen, as a clean OAuth posture. A third-party app holding admin scope is a
// shadow administrator nobody provisioned, and it would be reported as its own opposite.
func TestCoverageGaps_UnreadGrantsAreDeclared(t *testing.T) {
	ws := Workspace{Provider: "gworkspace", Org: "acme", Unavailable: []string{"oauth_grants"}}
	got := CoverageGaps(ws, time.Unix(0, 0))
	if len(got) != 1 {
		t.Fatalf("want 1 disclosure, got %d: %+v", len(got), got)
	}
	if got[0].Severity != types.SeverityInfo {
		t.Errorf("severity = %q; a check that did not run has no evidence for one", got[0].Severity)
	}
	if !strings.HasPrefix(got[0].RuleID, "coverage::") {
		t.Errorf("rule = %q; the coverage:: namespace is what keeps it out of the issue list "+
			"and the coverage counts", got[0].RuleID)
	}
	d := got[0].Description
	if !strings.Contains(d, "not a finding") {
		t.Error("the text must say it reports an absence of testing, not a problem observed")
	}
	if !strings.Contains(d, "admin scope") {
		t.Error("the text must say what the check would have found — otherwise a reader cannot judge whether the gap matters")
	}
}

// A gap must NEVER be inferred from an empty result. That ambiguity is the thing this
// resolves, and inferring would make a genuinely clean workspace produce a gap for every
// check that found nothing.
func TestCoverageGaps_NotInferredFromEmptiness(t *testing.T) {
	ws := Workspace{Provider: "okta", Org: "acme"} // no users, no grants, nothing recorded
	if got := CoverageGaps(ws, time.Unix(0, 0)); len(got) != 0 {
		t.Errorf("an empty workspace with no recorded failure declares nothing, got %+v", got)
	}
}

// A provider limit is STANDING — identical on every scan of every Google workspace,
// forever, and unchanged by anything the customer does. Emitted per scan it would arrive
// as new information every time, which is how a disclosure becomes the thing people learn
// to scroll past; and then the one that MATTERS, sitting beside it, gets scrolled past
// too. Same line internal/coverage draws between DeclaredGaps and UntestedClasses.
func TestCoverageGaps_ProviderLimitIsNotAPerScanFinding(t *testing.T) {
	ws := Workspace{Provider: "gworkspace", Org: "acme",
		ProviderLimits: []string{"oauth_publisher_verification"}}
	if got := CoverageGaps(ws, time.Unix(0, 0)); len(got) != 0 {
		t.Errorf("a standing provider limit must not be a per-scan finding, got %+v", got)
	}
}

// Assess must emit the disclosures alongside the posture findings, or the gate is
// bookkeeping nobody sees.
func TestAssess_EmitsCoverageGaps(t *testing.T) {
	ws := Workspace{
		Provider: "m365", Org: "acme",
		Users:       []User{{Email: "a@acme.test", Admin: true, MFA: true}},
		Unavailable: []string{"oauth_grants"},
	}
	got := Assess(ws, Options{Now: time.Unix(0, 0)})
	var gaps int
	for _, f := range got {
		if strings.HasPrefix(f.RuleID, "coverage::") {
			gaps++
		}
	}
	if gaps != 1 {
		t.Errorf("coverage disclosures in Assess output = %d, want 1: %+v", gaps, ruleIDs(got))
	}
}

// A hardened workspace with everything readable stays clean — the disclosure must not
// become background noise on every scan.
func TestAssess_CleanWorkspaceDeclaresNothing(t *testing.T) {
	ws := Workspace{
		Provider: "m365", Org: "acme",
		Users:   []User{{Email: "a@acme.test", Admin: true, MFA: true}},
		Domains: []DomainConfig{{Name: "acme.test", DMARC: "reject", SPF: true, DKIM: true, SPFAll: "-", DMARCPct: 100}},
	}
	for _, f := range Assess(ws, Options{Now: time.Unix(0, 0)}) {
		if strings.HasPrefix(f.RuleID, "coverage::") {
			t.Errorf("a workspace with nothing recorded as unreadable declared a gap: %s", f.RuleID)
		}
	}
}

// Unknown keys are ignored rather than rendered as an empty disclosure — a gap nobody can
// act on is worse than none.
func TestCoverageGaps_UnknownKeyIsIgnored(t *testing.T) {
	ws := Workspace{Provider: "okta", Org: "acme", Unavailable: []string{"something_we_never_defined"}}
	if got := CoverageGaps(ws, time.Unix(0, 0)); len(got) != 0 {
		t.Errorf("an undefined check key must be ignored, got %+v", got)
	}
}

func ruleIDs(fs []types.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}
