package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
)

func probesAt(stamp, snap string) *cloudagent.ProbeCoverage {
	return &cloudagent.ProbeCoverage{
		Tested: 2, Allowed: 2, Prober: "AWS iam:SimulatePrincipalPolicy",
		Freshness: cloudagent.ProofFreshness{SnapshotHash: snap, ObtainedAt: stamp},
	}
}

// A provider proof is a point-in-time answer and the finding is the only surface a human reads it on.
// Stating the rung without WHEN and AGAINST WHAT renders a proof taken three weeks ago against a
// since-re-scoped account identically to one taken a minute ago (ADR 0024 C4).
func TestCloudIssueToFinding_AProvenPathStatesWhenAndAgainstWhat(t *testing.T) {
	f := cloudIssueToFinding("f1", cloudagent.Issue{
		Target: "arn:aws:s3:::crown", Severity: "critical",
		ProviderConfirmed: true, AuthorizationCoverage: "2/2",
	}, probesAt("2026-08-23T11:00:00Z", "abc123def456789"))

	if !strings.Contains(f.Description, "2026-08-23T11:00:00Z") {
		t.Error("a provider proof does not say when it was obtained")
	}
	if !strings.Contains(f.Description, "abc123def456") {
		t.Error("a provider proof does not name the account state it was evaluated against, so nobody can re-check it")
	}
	if !strings.Contains(f.Description, "re-check") {
		t.Error("the proof does not tell the reader it needs re-checking after a policy change")
	}
}

// The refusal that keeps the line honest: a config-possible path has NO provider proof, so stamping
// it with a snapshot hash and a timestamp would dress our own graph up as something the provider had
// been asked about. Silence costs nothing; a provenance line on an unproven claim is the overclaim
// this rung exists to prevent.
func TestCloudIssueToFinding_AnUnprovenPathGetsNoProvenance(t *testing.T) {
	f := cloudIssueToFinding("f1", cloudagent.Issue{Target: "arn:aws:s3:::crown", Severity: "critical"},
		probesAt("2026-08-23T11:00:00Z", "abc123def456789"))

	if strings.Contains(f.Description, "2026-08-23T11:00:00Z") ||
		strings.Contains(f.Description, "account state") {
		t.Fatalf("a config-possible path carries provider-proof provenance:\n%s", f.Description)
	}
	if !strings.Contains(f.Description, "config-possible") {
		t.Error("the rung line itself went missing")
	}
}

// A PARTIAL proof is real evidence about the hops it covers, so it earns provenance too — otherwise
// the only thing distinguishing it from an unproven path is prose.
func TestCloudIssueToFinding_APartialProofStillStatesItsProvenance(t *testing.T) {
	f := cloudIssueToFinding("f1", cloudagent.Issue{
		Target: "arn:aws:s3:::crown", Severity: "critical", AuthorizationCoverage: "1/3",
	}, probesAt("2026-08-23T11:00:00Z", "abc123def456789"))
	if !strings.Contains(f.Description, "2026-08-23T11:00:00Z") {
		t.Error("a partial proof is still a provider answer and must date itself")
	}
}

// No prober wired, or no answer obtained, means there is nothing honest to date. Saying nothing is
// correct; inventing a stamp is not.
func TestCloudIssueToFinding_NoProbeMeansNoProvenanceLine(t *testing.T) {
	is := cloudagent.Issue{Target: "arn:aws:s3:::crown", Severity: "critical", ProviderConfirmed: true, AuthorizationCoverage: "2/2"}
	for name, probes := range map[string]*cloudagent.ProbeCoverage{
		"no prober configured":           nil,
		"prober ran but stamped nothing": {Tested: 1, Freshness: cloudagent.ProofFreshness{SnapshotHash: "abc"}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := cloudIssueToFinding("f1", is, probes).Description; strings.Contains(got, "Obtained at") {
				t.Fatalf("dated a proof that has no recorded time:\n%s", got)
			}
		})
	}
}
