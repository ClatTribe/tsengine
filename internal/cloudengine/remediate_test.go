package cloudengine

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestRemediation_GeneratesAndSelfVerifies asserts the generator turns attack
// paths into applyable artifacts AND proves the policy-based ones effective by
// re-evaluating them through cloudiam.Authorize.
func TestRemediation_GeneratesAndSelfVerifies(t *testing.T) {
	a := &types.AIAssessment{Paths: []types.AttackPath{
		{ID: "acp-001", Graph: types.PathGraph{Edges: []types.PathEdge{
			{From: "internet", To: "ec2", Kind: string(cloudgraph.EdgeNetworkReach)},
			{From: "ec2", To: "web-role", Kind: string(cloudgraph.EdgeRunsAs)},
			{From: "web-role", To: "pii", Kind: string(cloudgraph.EdgeHasAccess)},
		}}},
		{ID: "acp-002", Graph: types.PathGraph{Edges: []types.PathEdge{
			{From: "internet", To: "ec2b", Kind: string(cloudgraph.EdgeNetworkReach)},
			{From: "ec2b", To: "deploy-role", Kind: string(cloudgraph.EdgeRunsAs)},
			{From: "deploy-role", To: "admin", Kind: string(cloudgraph.EdgePrivesc)},
		}}},
	}}

	rs := GenerateRemediations(a)
	if len(rs) != 2 {
		t.Fatalf("want 2 artifacts, got %d", len(rs))
	}
	byPath := map[string]RemediationArtifact{}
	for _, r := range rs {
		byPath[r.PathID] = r
	}

	// acp-001 should cut the has_access edge with a verified IAM Deny.
	access := byPath["acp-001"]
	if access.Kind != "iam_policy" || access.CutsEdge.Kind != string(cloudgraph.EdgeHasAccess) {
		t.Errorf("acp-001: want iam_policy cutting has_access, got kind=%s edge=%s", access.Kind, access.CutsEdge.Kind)
	}
	if !access.Verified {
		t.Error("acp-001: the IAM Deny must self-verify (cloudiam confirms the read is denied)")
	}

	// acp-002 should cut the privesc edge with a verified SCP deny.
	privesc := byPath["acp-002"]
	if privesc.Kind != "aws_scp" || privesc.CutsEdge.Kind != string(cloudgraph.EdgePrivesc) {
		t.Errorf("acp-002: want aws_scp cutting privesc, got kind=%s edge=%s", privesc.Kind, privesc.CutsEdge.Kind)
	}
	if !privesc.Verified {
		t.Error("acp-002: the SCP must self-verify (cloudiam confirms the escalation action is denied)")
	}
}
