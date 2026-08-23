package platformapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// countingProber answers a fixed verdict and records how many live calls were spent — the budget
// property is as much the point as the verdict (ADR 0024 C10: read-only is not free).
type countingProber struct {
	verdict cloudagent.Verdict
	calls   int
}

func (p *countingProber) CanPerform(context.Context, string, string, string) (cloudagent.ProbeResult, error) {
	p.calls++
	return cloudagent.ProbeResult{Verdict: p.verdict, Detail: "matched AllowProdRead"}, nil
}
func (p *countingProber) Coverage() string { return "counting" }

// An UNCONDITIONED GitHub trust: no `sub` condition at all, so any repository on GitHub can assume it.
const openTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
  "Action":"sts:AssumeRoleWithWebIdentity"}]}`

// A CORRECTLY SCOPED trust: one repository, pinned.
const scopedTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
  "Action":"sts:AssumeRoleWithWebIdentity",
  "Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/web:ref:refs/heads/main"}}}]}`

func rawWith(trust string, sensitive bool) awsinventory.RawAWS {
	return awsinventory.RawAWS{
		AccountID: "111122223333",
		Roles:     []awsinventory.RawIAMRole{{ARN: "arn:aws:iam::111122223333:role/deploy", Name: "deploy", TrustPolicyJSON: trust}},
		Buckets:   []awsinventory.RawBucket{{Name: "customer-exports", Sensitive: sensitive}},
	}
}

func weaknessFinding() types.Finding {
	return types.Finding{
		ID: "g1", RuleID: "ghoidc::unconditioned-trust", Tool: "ghoidc",
		Severity: types.SeverityHigh, Endpoint: "arn:aws:iam::111122223333:role/deploy",
		Title: "Role deploy trusts GitHub Actions with no subject condition",
	}
}

// THE JOIN. Separately each half is deferrable — plenty of broadly-trusted roles hold nothing.
// Together they are the finding, and the reach must reach the EXISTING weakness rather than a second
// row, or the original still reads as deferrable.
func TestAnnotateCIReach_AProvenReachUpgradesTheWeakness(t *testing.T) {
	p := &countingProber{verdict: cloudagent.VerdictAllow}
	out := annotateCIReach(context.Background(), rawWith(openTrust, true), []types.Finding{weaknessFinding()}, p)

	if len(out) != 1 {
		t.Fatalf("the reach must annotate the existing finding, not add one: got %d", len(out))
	}
	if !strings.Contains(out[0].Description, "customer-exports") {
		t.Errorf("the proven reach is not stated on the finding:\n%s", out[0].Description)
	}
	if out[0].Severity != types.SeverityCritical {
		t.Errorf("severity = %q; a trust weakness that demonstrably reaches declared-sensitive data "+
			"is not the same finding as one that reaches nothing", out[0].Severity)
	}
	if !strings.Contains(out[0].Description, "not a demonstrated exploit") {
		t.Errorf("the annotation claims more than authorization (ADR 0024 C1):\n%s", out[0].Description)
	}
}

// A CORRECTLY SCOPED trust refuses at the trust half, and ciproof.Prove then spends NO provider call.
// That is what makes probing every role affordable — and read-only is not free (C10).
func TestAnnotateCIReach_AScopedTrustCostsNoProviderCall(t *testing.T) {
	p := &countingProber{verdict: cloudagent.VerdictAllow}
	out := annotateCIReach(context.Background(), rawWith(scopedTrust, true), []types.Finding{weaknessFinding()}, p)

	if p.calls != 0 {
		t.Errorf("spent %d provider calls on a role whose trust already refused the actor", p.calls)
	}
	if out[0].Severity != types.SeverityHigh || strings.Contains(out[0].Description, "customer-exports") {
		t.Error("a role that refused the probe actor had its finding altered anyway")
	}
}

// A DENY or an UNKNOWN proves nothing about reach — and must not WEAKEN the weakness either. ghoidc
// found it by reading the policy; this probe was never evidence against that.
func TestAnnotateCIReach_ANonAllowVerdictLeavesTheFindingAlone(t *testing.T) {
	for name, v := range map[string]cloudagent.Verdict{
		"denied":  cloudagent.VerdictDeny,
		"unknown": cloudagent.VerdictUnknown,
	} {
		t.Run(name, func(t *testing.T) {
			before := weaknessFinding()
			out := annotateCIReach(context.Background(), rawWith(openTrust, true),
				[]types.Finding{before}, &countingProber{verdict: v})
			if out[0].Severity != before.Severity || out[0].Description != before.Description {
				t.Fatalf("a %s verdict changed the finding:\n%s", name, out[0].Description)
			}
		})
	}
}

// Sensitivity is DECLARED by the collector, never inferred from a bucket name — the same refusal
// dataplatform makes. With nothing declared there is nothing worth spending the budget to ask about.
func TestAnnotateCIReach_NoDeclaredCrownJewelAsksNothing(t *testing.T) {
	p := &countingProber{verdict: cloudagent.VerdictAllow}
	out := annotateCIReach(context.Background(), rawWith(openTrust, false), []types.Finding{weaknessFinding()}, p)
	if p.calls != 0 {
		t.Errorf("spent %d calls probing reach to a bucket nobody declared sensitive", p.calls)
	}
	if out[0].Severity != types.SeverityHigh {
		t.Error("the finding was escalated without a proven reach")
	}
}

// No prober wired is a first-class answer, not a failure: the findings pass through untouched.
func TestAnnotateCIReach_NoProberIsANoOp(t *testing.T) {
	in := []types.Finding{weaknessFinding()}
	out := annotateCIReach(context.Background(), rawWith(openTrust, true), in, nil)
	if len(out) != 1 || out[0].Severity != types.SeverityHigh || out[0].Description != in[0].Description {
		t.Fatal("a deployment with no dry-run path had its findings altered")
	}
}

// Only ghoidc findings are joined. A drift or SAML finding that happens to carry a role ARN as its
// endpoint is a different claim, and attaching a CI-federation summary to it would misattribute the
// reach to a defect that is not about federation at all.
func TestAnnotateCIReach_OnlyGhoidcFindingsAreJoined(t *testing.T) {
	other := weaknessFinding()
	other.RuleID = "samltrust::missing-audience-condition"
	out := annotateCIReach(context.Background(), rawWith(openTrust, true), []types.Finding{other},
		&countingProber{verdict: cloudagent.VerdictAllow})
	if strings.Contains(out[0].Description, "customer-exports") {
		t.Fatalf("a SAML finding was annotated with a GitHub-federation reach:\n%s", out[0].Description)
	}
}

// THE ROUTING TEST, and it exists because its absence was caught by mutation rather than by review.
//
// Deleting the annotateCIReach call from the ingest COMPILED and every unit test above still passed —
// the built-but-not-wired gap reproduced inside the tests written to prove the wiring, which is
// exactly the defect ADR 0024 C11 describes and the second time this campaign has had to catch it in
// its own work. A join nothing calls is a join that does not exist.
func TestCloudInventory_TheIngestRunsTheReachJoin(t *testing.T) {
	st := store.NewMemory()
	withAWSConnection(t, st, "t1", platform.ConnActive)

	h := NewHandler(Deps{
		Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		CloudSnapshots: cloudsnap.NewMemStore(),
		CloudProber: func(platform.Connection) cloudagent.ExploitProber {
			return &countingProber{verdict: cloudagent.VerdictAllow}
		},
	})
	body, err := json.Marshal(rawWith(openTrust, true))
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(h, "POST", "/v1/cloud/inventory", "t1", string(body)); rec.Code != 200 {
		t.Fatalf("ingest failed (%d): %s", rec.Code, rec.Body.String())
	}

	found, err := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var joined bool
	for _, f := range found {
		if strings.HasPrefix(f.RuleID, "ghoidc::") && strings.Contains(f.Description, "customer-exports") {
			joined = true
		}
	}
	if !joined {
		t.Fatal("the stored CI-identity finding carries no reach annotation, so the join never ran " +
			"in the ingest — the primitive is correct and the product does not use it")
	}
}
