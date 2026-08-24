package l15

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// enrich_rung_test.go exists because a mutation found nothing guarding it: deleting the line that
// stamps the evidence rung left every test in the tree passing, while findings silently lost the
// field, the API stopped returning it and the finding page fell back to the raw verification word —
// the exact state ADR 0029 D2d was written to end.
//
// The stamp is one line in a loop. Those are the ones that vanish in a refactor.

func TestEnrich_StampsTheEvidenceRung(t *testing.T) {
	t.Setenv("TSENGINE_L15_DISABLED", "")

	out := Enrich([]types.Finding{{
		ID: "f1", Tool: "web-investigate", RuleID: "web-agent::sqli", Severity: types.SeverityHigh,
		Endpoint: "https://app.example.com/search?q=1", VerificationStatus: types.VerificationVerified,
	}})

	if len(out) != 1 {
		t.Fatalf("enrichment dropped the finding: got %d", len(out))
	}
	if out[0].Rung == "" {
		t.Fatal("the chain did not stamp a rung. Nothing downstream re-derives it, so the API returns " +
			"no rung, the finding page falls back to the three-value verification word, and the " +
			"distinction between an exploit we ran and a permission we checked is gone again.")
	}
	if out[0].Rung != types.RungExploited {
		t.Errorf("rung = %q, want %q for a verified finding from the offensive agent", out[0].Rung, types.RungExploited)
	}
}

func TestEnrich_StampsTheRungLastSoItSeesTheFinishedFinding(t *testing.T) {
	// The confidence hook sets VerificationStatus in the finalize pass, and the rung reads it.
	// Deriving before the chain finished would record a rung for a finding the chain had not finished
	// describing — a scanner finding that the corroborator was about to upgrade would be stamped at
	// the floor and stay there.
	t.Setenv("TSENGINE_L15_DISABLED", "")

	// Two independent tools reporting the same thing. The corroborator groups on ENDPOINT + CWE —
	// the first version of this fixture omitted the CWE, so the key was empty, nothing grouped, and
	// the test SKIPPED. A skip is green, which is the §14.2 rule 6 failure it would have been guarding
	// against; the fixture is now built to actually trip the hook.
	out := Enrich([]types.Finding{
		{ID: "a", Tool: "trivy", RuleID: "trivy::CVE-2024-1", Severity: types.SeverityHigh,
			Endpoint: "pkg:npm/left-pad@1.0.0", CWE: []string{"CWE-1035"}},
		{ID: "b", Tool: "grype", RuleID: "grype::CVE-2024-1", Severity: types.SeverityHigh,
			Endpoint: "pkg:npm/left-pad@1.0.0", CWE: []string{"CWE-1035"}},
	})

	var sawCorroborated bool
	for _, f := range out {
		if f.VerificationStatus == types.VerificationCorroborated {
			sawCorroborated = true
			if f.Rung != types.RungCorroborated {
				t.Errorf("a finding the chain UPGRADED to corroborated carries rung %q — the rung was "+
					"derived before the chain finished, so it describes an earlier version of the finding",
					f.Rung)
			}
		}
	}
	if !sawCorroborated {
		t.Fatal("no finding came out corroborated, so this test asserted nothing. Two distinct tools " +
			"reported the same CWE at the same endpoint; if the corroborator's key changed, fix the " +
			"fixture — do not let this pass by skipping.")
	}
}

func TestEnrich_AblationLeavesNoRung(t *testing.T) {
	// TSENGINE_L15_DISABLED makes Enrich the identity function (§14.1), which is what makes the
	// L1-vs-L1.5 delta measurable. A rung stamped anyway would be enrichment leaking through the
	// ablation and would quietly inflate the L1 baseline.
	t.Setenv("TSENGINE_L15_DISABLED", "1")

	out := Enrich([]types.Finding{{
		ID: "f2", Tool: "web-investigate", VerificationStatus: types.VerificationVerified,
	}})

	if out[0].Rung != "" {
		t.Errorf("the ablation flag is set and the chain still stamped rung %q — with L1.5 disabled "+
			"Enrich must be the identity function", out[0].Rung)
	}
}
