package remediate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The deactivation targets exactly the key id the finding itself carries, binds to the AWS
// connection, and is tier 2 (gated). A finding naming no id, or a non-AWS connection, gets nothing.
func TestKeyDeactivateAction_TargetsOnlyTheKeyTheFindingNames(t *testing.T) {
	aws := platform.Connection{ID: "c-aws", TenantID: "t1", Kind: platform.ConnAWS}
	n := 0
	gen := func() string { n++; return "id" }
	f := types.Finding{ID: "f1", RuleID: "gitleaks::aws-access-key", Title: "AWS key AKIAIOSFODNN7EXAMPLE in config/prod.env", Endpoint: "config/prod.env:3"}
	if !IsLeakedAWSKey(f) {
		t.Fatal("a finding carrying an AKIA id is a leaked key")
	}
	act, ok := KeyDeactivateAction(f, aws, gen)
	if !ok {
		t.Fatal("expected an action")
	}
	if act.Kind != platform.ActApplyConfig || act.Tier != tierApplyConfig || act.ConnectionID != "c-aws" || act.TenantID != "t1" || act.FindingID != "f1" {
		t.Errorf("action shape: %+v", act)
	}
	if act.Payload["remediation_type"] != rtypeKeyDeactivate || act.Payload["target"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("payload: %+v", act.Payload)
	}
	if rem, _ := act.Payload["remediation"].(string); !strings.Contains(rem, "INACTIVE") || !strings.Contains(rem, "does not delete") {
		t.Errorf("the human must be told it deactivates, reversibly, and does not delete: %q", rem)
	}
	// The live type must NOT be among the runbook-only remediations, or the deliverer would file a
	// ticket instead of calling the connector.
	if cloudRunbookRemediations[rtypeKeyDeactivate] {
		t.Error("aws_key_deactivate is a live write, not a runbook")
	}

	vague := types.Finding{ID: "f2", RuleID: "trufflehog::aws", Title: "AWS secret access key detected", Endpoint: "x.env:1"}
	if !IsLeakedAWSKey(vague) {
		t.Error("a secret-access-key finding is a leaked-key finding")
	}
	if _, ok := KeyDeactivateAction(vague, aws, gen); ok {
		t.Error("a finding that names no key id must not produce a deactivation — that would be a guess")
	}
	if _, ok := KeyDeactivateAction(f, platform.Connection{ID: "c-gh", Kind: platform.ConnGitHub}, gen); ok {
		t.Error("only an AWS connection can deactivate an AWS key")
	}
}
