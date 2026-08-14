package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func exIssue(key, endpoint string, findingIDs ...string) crossdetect.Issue {
	return crossdetect.Issue{
		Key: key, Title: "SQL injection in search", Severity: "critical",
		Endpoint: endpoint, FindingIDs: findingIDs, Count: len(findingIDs),
	}
}

func exFinding(id string) types.Finding {
	return types.Finding{
		ID: id, RuleID: "nuclei::sqli-error-based", Tool: "nuclei",
		Severity: types.SeverityCritical, CWE: []string{"CWE-89"},
		Title: "SQL injection in search", Endpoint: "https://app.acme.com/search?q=",
	}
}

// THE DELIVERY TEST: every issue the API returns carries an explanation a founder can act on.
func TestAnnotateExplanations_EveryIssueGetsOne(t *testing.T) {
	issues := []crossdetect.Issue{exIssue("k1", "https://app.acme.com/search?q=", "f-1")}
	got := annotateExplanations(issues, []types.Finding{exFinding("f-1")}, nil, nil)
	e, ok := got["k1"]
	if !ok {
		t.Fatal("issue got no explanation — the list is still rule ids")
	}
	if e.Headline == "" || e.What == "" || e.Fix == "" || e.UrgencyLabel == "" {
		t.Errorf("explanation is incomplete: %+v", e)
	}
	if !strings.Contains(strings.ToLower(e.What), "database") {
		t.Errorf("the CWE-89 class was not translated: %q", e.What)
	}
}

// ── BLAST RADIUS STAYS GROUNDED THROUGH THE WIRING ───────────────────────────────────────────────

// A chain that reaches a crown jewel must produce a named blast radius on the findings that LEAD there.
func TestAnnotateExplanations_ReachComesFromTheChain(t *testing.T) {
	chains := []correlate.Chain{{
		Severity: "critical",
		Steps: []correlate.Step{
			{AssetType: "repository", FindingID: "f-1", Title: "leaked key"},
			{AssetType: "cloud_account", FindingID: "f-2", Title: "admin role", CrownJewel: true},
		},
	}}
	got := annotateExplanations(
		[]crossdetect.Issue{exIssue("k1", "repo/config.tf", "f-1")},
		[]types.Finding{exFinding("f-1")}, nil, chains)
	if !strings.Contains(got["k1"].Why, "your cloud account") {
		t.Errorf("a proven chain to the cloud account was not surfaced as blast radius: %q", got["k1"].Why)
	}
}

// THE GROUNDING RULE: a finding that IS the crown does not "reach" itself, and steps AFTER a crown are
// not consequences of it. Only earlier steps lead there. Without this, every finding in a chain would
// claim to reach the crown — inflating blast radius, which is the field most likely to make someone act.
func TestAnnotateExplanations_OnlyEarlierStepsReachTheCrown(t *testing.T) {
	chains := []correlate.Chain{{
		Severity: "critical",
		Steps: []correlate.Step{
			{AssetType: "repository", FindingID: "f-1", Title: "leaked key"},
			{AssetType: "cloud_account", FindingID: "f-crown", Title: "admin", CrownJewel: true},
			{AssetType: "api", FindingID: "f-after", Title: "later step"},
		},
	}}
	got := annotateExplanations(
		[]crossdetect.Issue{
			exIssue("k-crown", "arn:crown", "f-crown"),
			exIssue("k-after", "https://api/x", "f-after"),
		},
		[]types.Finding{exFinding("f-crown"), exFinding("f-after")}, nil, chains)

	if strings.Contains(got["k-crown"].Why, "your cloud account") {
		t.Error("the crown jewel was reported as reaching ITSELF — inflated blast radius")
	}
	if strings.Contains(got["k-after"].Why, "your cloud account") {
		t.Error("a step AFTER the crown was reported as reaching it — that is not a consequence of it")
	}
}

// No chains at all → the explanation must ADMIT the reach is untraced, never imply we looked.
func TestAnnotateExplanations_NoChainsAdmitsUntraced(t *testing.T) {
	got := annotateExplanations(
		[]crossdetect.Issue{exIssue("k1", "https://app/x", "f-1")},
		[]types.Finding{exFinding("f-1")}, nil, nil)
	if !strings.Contains(strings.ToLower(got["k1"].Why), "not traced") {
		t.Errorf("with no correlation run, the explanation did not admit the blast radius is unknown: %q", got["k1"].Why)
	}
}

// ── DEGRADATION ──────────────────────────────────────────────────────────────────────────────────

// An issue whose findings are missing from the store still gets an explanation from its own fields —
// degraded, never blank. A blank row is indistinguishable from "nothing wrong".
func TestAnnotateExplanations_MissingFindingsStillExplain(t *testing.T) {
	got := annotateExplanations(
		[]crossdetect.Issue{exIssue("k1", "https://app/x", "f-gone")},
		nil, nil, nil)
	if got["k1"].Headline == "" || got["k1"].What == "" {
		t.Errorf("an issue with unresolvable findings produced a blank explanation: %+v", got["k1"])
	}
}

// The asset the customer named should appear, and a non-matching endpoint must NOT borrow another
// asset's name — that would put the wrong system in front of the reader.
func TestAnnotateExplanations_AssetLabelIsLongestLiteralMatch(t *testing.T) {
	assets := []platform.Asset{
		{ID: "a1", Target: "acme.com"},
		{ID: "a2", Target: "api.acme.com"},
	}
	got := annotateExplanations(
		[]crossdetect.Issue{exIssue("k1", "https://api.acme.com/search", "f-1")},
		[]types.Finding{exFinding("f-1")}, assets, nil)
	if !strings.Contains(got["k1"].Headline, "api.acme.com") {
		t.Errorf("the more specific asset did not win: %q", got["k1"].Headline)
	}

	unrelated := annotateExplanations(
		[]crossdetect.Issue{exIssue("k2", "https://other.example/x", "f-1")},
		[]types.Finding{exFinding("f-1")}, assets, nil)
	if strings.Contains(unrelated["k2"].Headline, "acme.com") {
		t.Errorf("an unrelated endpoint borrowed an asset's name: %q", unrelated["k2"].Headline)
	}
}

// Runtime attack observation must reach the explanation's urgency — it's the strongest evidence we have.
func TestAnnotateExplanations_UnderAttackIsUrgent(t *testing.T) {
	iss := exIssue("k1", "https://app/x", "f-1")
	iss.Attacked = true
	got := annotateExplanations([]crossdetect.Issue{iss}, []types.Finding{exFinding("f-1")}, nil, nil)
	if got["k1"].UrgencyLabel != "Fix today" {
		t.Errorf("an endpoint under live attack was graded %q", got["k1"].UrgencyLabel)
	}
}

func TestAnnotateExplanations_EmptyInputIsNil(t *testing.T) {
	if got := annotateExplanations(nil, nil, nil, nil); got != nil {
		t.Errorf("no issues should yield nil, got %v", got)
	}
}
