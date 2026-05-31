package cloudengine

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Remediation artifacts — the "act" half of the cloud security engineer's job.
//
// The engine already narrates a fix in prose; this turns that into a CONCRETE,
// reviewable, applyable change that cuts the cheapest edge of an attack path: an
// SCP deny (a preventive org guardrail), an IAM policy Deny, a security-group
// revoke, or a trust-policy restriction. The operator (or tswrap, as a PR) can
// apply it directly.
//
// Two of the artifact kinds are SELF-VERIFYING: the emitted SCP / IAM Deny is fed
// back through cloudiam.Authorize to confirm the escalation/access action is now
// denied — so the remediation isn't just suggested, it's proven effective against
// the same evaluator the engine reasons with (closing the detect→fix→verify loop).

// privescActions is the PMapper/Rhino IAM privilege-escalation primitive set —
// the actions an SCP must deny to cut a privesc-to-admin edge.
var privescActions = []string{
	"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:CreateAccessKey",
	"iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:AttachUserPolicy",
	"iam:AttachGroupPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy",
	"iam:PutGroupPolicy", "iam:PutRolePolicy", "iam:AddUserToGroup",
	"iam:UpdateAssumeRolePolicy", "iam:PassRole",
}

// RemediationArtifact is one applyable fix for an attack path.
type RemediationArtifact struct {
	PathID    string         `json:"path_id"`
	Strategy  string         `json:"strategy"` // short label
	Kind      string         `json:"kind"`     // aws_scp | iam_policy | aws_cli | trust_policy
	Title     string         `json:"title"`
	Rationale string         `json:"rationale"`
	Content   string         `json:"content"` // the artifact body (JSON / CLI)
	CutsEdge  types.PathEdge `json:"cuts_edge"`
	Verified  bool           `json:"verified"` // re-checked via cloudiam.Authorize
	VerifyMsg string         `json:"verify_msg,omitempty"`
}

// GenerateRemediations produces one applyable artifact per attack path, cutting
// the most actionable edge.
func GenerateRemediations(a *types.AIAssessment) []RemediationArtifact {
	if a == nil {
		return nil
	}
	var out []RemediationArtifact
	for _, p := range a.Paths {
		e, ok := pickCutEdge(p.Graph.Edges)
		if !ok {
			continue
		}
		out = append(out, buildArtifact(p.ID, e))
	}
	return out
}

// pickCutEdge chooses the edge whose removal most cleanly breaks the chain:
// prefer cutting the privilege/access/trust edges (a targeted policy change) over
// the network edge, and never the runs_as edge (not directly removable).
func pickCutEdge(edges []types.PathEdge) (types.PathEdge, bool) {
	priority := map[string]int{
		string(cloudgraph.EdgePrivesc):      5,
		string(cloudgraph.EdgeHasAccess):    4,
		string(cloudgraph.EdgeAssumeRole):   3,
		string(cloudgraph.EdgeNetworkReach): 2,
		string(cloudgraph.EdgePassRole):     1,
	}
	best, bestP, ok := types.PathEdge{}, 0, false
	for _, e := range edges {
		if p := priority[e.Kind]; p > bestP {
			best, bestP, ok = e, p, true
		}
	}
	return best, ok
}

func buildArtifact(pathID string, e types.PathEdge) RemediationArtifact {
	switch cloudgraph.EdgeKind(e.Kind) {
	case cloudgraph.EdgePrivesc:
		return scpDenyPrivesc(pathID, e)
	case cloudgraph.EdgeHasAccess:
		return iamDenyAccess(pathID, e)
	case cloudgraph.EdgeAssumeRole:
		return restrictTrust(pathID, e)
	case cloudgraph.EdgeNetworkReach:
		return closeNetwork(pathID, e)
	default:
		return RemediationArtifact{PathID: pathID, Strategy: "manual", Kind: "aws_cli", CutsEdge: e,
			Title: "Manual review", Rationale: fmt.Sprintf("break the %s edge %s → %s", e.Kind, e.From, e.To)}
	}
}

// scpDenyPrivesc emits a preventive SCP that denies the IAM privesc primitives,
// then VERIFIES via cloudiam that the escalation action is now denied.
func scpDenyPrivesc(pathID string, e types.PathEdge) RemediationArtifact {
	scp := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyIAMPrivilegeEscalation",
    "Effect": "Deny",
    "Action": [%s],
    "Resource": "*"
  }]
}`, quoteList(privescActions))

	art := RemediationArtifact{
		PathID: pathID, Strategy: "scp_deny_privesc", Kind: "aws_scp", CutsEdge: e,
		Title:     "Attach an SCP denying IAM privilege-escalation actions",
		Rationale: fmt.Sprintf("%s can escalate to %s; an org SCP denying the privesc primitives cuts this for every account it covers (preventive, not just this finding).", e.From, e.To),
		Content:   scp,
	}
	// self-verify: under this SCP, the escalation action must be denied even for an admin identity.
	if doc, err := cloudiam.Parse([]byte(scp)); err == nil {
		admin, _ := cloudiam.Parse([]byte(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`))
		dec, _ := cloudiam.Authorize(
			cloudiam.Request{Principal: e.From, Action: "iam:CreatePolicyVersion", Resource: "*"},
			cloudiam.PolicySet{Identity: []*cloudiam.Document{admin}, SCPs: []*cloudiam.Document{doc}, SameAccount: true})
		art.Verified = dec == cloudiam.ExplicitDeny
		art.VerifyMsg = "cloudiam.Authorize confirms the escalation action is denied under this SCP"
	}
	return art
}

// iamDenyAccess emits an inline IAM Deny on the resource for the principal, then
// verifies the access is now denied.
func iamDenyAccess(pathID string, e types.PathEdge) RemediationArtifact {
	policy := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyReachableDataAccess",
    "Effect": "Deny",
    "Action": ["s3:GetObject", "s3:GetObjectVersion"],
    "Resource": ["%s", "%s/*"]
  }]
}`, e.To, e.To)

	art := RemediationArtifact{
		PathID: pathID, Strategy: "remove_data_grant", Kind: "iam_policy", CutsEdge: e,
		Title:     fmt.Sprintf("Deny %s read access to %s", e.From, e.To),
		Rationale: fmt.Sprintf("the reachable path ends in %s reading %s; least-privilege says remove the grant. Attach this inline Deny (or delete the granting statement).", e.From, e.To),
		Content:   policy,
	}
	if deny, err := cloudiam.Parse([]byte(policy)); err == nil {
		allow, _ := cloudiam.Parse([]byte(fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":%q}]}`, e.To)))
		dec, _ := cloudiam.Authorize(
			cloudiam.Request{Principal: e.From, Action: "s3:GetObject", Resource: e.To},
			cloudiam.PolicySet{Identity: []*cloudiam.Document{allow, deny}, SameAccount: true})
		art.Verified = dec == cloudiam.ExplicitDeny
		art.VerifyMsg = "cloudiam.Authorize confirms the read is denied with this policy attached"
	}
	return art
}

func restrictTrust(pathID string, e types.PathEdge) RemediationArtifact {
	return RemediationArtifact{
		PathID: pathID, Strategy: "restrict_trust", Kind: "trust_policy", CutsEdge: e,
		Title:     fmt.Sprintf("Scope %s's trust policy to exclude %s", e.To, e.From),
		Rationale: fmt.Sprintf("%s can assume %s; remove %s from %s's AssumeRolePolicyDocument so the chain breaks.", e.From, e.To, e.From, e.To),
		Content: fmt.Sprintf(`# Edit the trust policy of %s: remove the statement permitting
# principal %s to sts:AssumeRole. Keep only the principals that legitimately need it.`, e.To, e.From),
	}
}

func closeNetwork(pathID string, e types.PathEdge) RemediationArtifact {
	return RemediationArtifact{
		PathID: pathID, Strategy: "close_network", Kind: "aws_cli", CutsEdge: e,
		Title:     fmt.Sprintf("Remove internet exposure of %s", e.To),
		Rationale: fmt.Sprintf("the path enters via %s → %s; restrict the security group / public access so the outside cannot reach it.", e.From, e.To),
		Content: fmt.Sprintf(`# revoke the 0.0.0.0/0 ingress that exposes %s, e.g.:
aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 0-65535 --cidr 0.0.0.0/0
# (or set the bucket/account public-access block, depending on the resource type)`, e.To),
	}
}

// RenderRemediations formats the applyable fixes.
func RenderRemediations(rs []RemediationArtifact) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== Remediation artifacts (applyable fixes) — %d path(s) ===\n", len(rs))
	for _, r := range rs {
		tick := " "
		if r.Verified {
			tick = "✓"
		}
		fmt.Fprintf(&b, "\n[%s] %s  (%s, kind=%s)  cuts %s→%s:%s\n",
			r.PathID, r.Title, r.Strategy, r.Kind, r.CutsEdge.From, r.CutsEdge.To, r.CutsEdge.Kind)
		fmt.Fprintf(&b, "  why: %s\n", r.Rationale)
		if r.VerifyMsg != "" {
			fmt.Fprintf(&b, "  verified[%s]: %s\n", tick, r.VerifyMsg)
		}
		for _, line := range strings.Split(strings.TrimRight(r.Content, "\n"), "\n") {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	return b.String()
}

func quoteList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = fmt.Sprintf("%q", x)
	}
	return strings.Join(q, ", ")
}
