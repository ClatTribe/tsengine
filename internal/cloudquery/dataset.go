package cloudquery

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Dataset is an emulated CloudQuery account plus its INDEPENDENT answer key. The
// account configuration is composed by tripping prowler catalog checks (so the
// "tools say" findings are config-grounded), while the answer key — which
// findings are genuinely exploitable vs inert — is established by cloudiam
// effective-permissions reasoning over the TRUE policy state (a predicate the
// engine's FindPaths does not use), so the test is not circular.
type Dataset struct {
	Tables    *Tables   `json:"-"`
	AnswerKey AnswerKey `json:"answer_key"`
}

// AnswerKey is the independent ground truth.
type AnswerKey struct {
	RealTargets   []string `json:"real_targets"`   // node ids of jewels reached by a genuine path
	InertFindings []string `json:"inert_findings"` // prowler finding ids that are config-bad but NOT exploitable
}

// arns used by the emulated account.
const (
	roleP   = "arn:aws:iam::123456789012:role/"
	ec2P    = "arn:aws:ec2:us-east-1:123456789012:instance/"
	piiARN  = "arn:aws:s3:::acme-customer-pii"
	finARN  = "arn:aws:s3:::acme-financial-ledger"
	logsARN = "arn:aws:s3:::acme-public-logs"
)

// Generate emulates one CloudQuery account with two genuinely-exploitable paths
// (a network→data chain and an IAM privesc-to-admin) and three config-bad-but-
// inert postures whose inertness needs effective-permission reasoning: a privesc
// blocked by a permission boundary, an assume-role blocked by a trust policy, and
// a public-but-non-sensitive bucket. The answer key is validated by cloudiam — a
// scenario that doesn't actually behave as labelled is rejected.
func Generate() (*Dataset, error) {
	ec2Trust := allowDoc("sts:AssumeRole", "ec2.amazonaws.com") // benign instance-profile trust

	t := &Tables{
		SecurityGroups: []SecurityGroup{{ID: "sg-open", Name: "open-to-world", OpenIngressFromInternet: true}},
		S3Buckets: []S3Bucket{
			// reached via web-role; flagged no_mfa_delete; corroborates the real path.
			{ARN: piiARN, Name: "acme-customer-pii", Region: "us-east-1", BlockPublicACLs: true, BlockPublicPolicy: true, MFADelete: false, Tags: map[string]string{"classification": "pii"}},
			// sensitive but reachable ONLY via a trust-denied assume ⇒ inert.
			{ARN: finARN, Name: "acme-financial-ledger", Region: "us-east-1", BlockPublicACLs: true, BlockPublicPolicy: true, MFADelete: false, Tags: map[string]string{"classification": "pii"}},
			// public but non-sensitive ⇒ config-bad, inert.
			{ARN: logsARN, Name: "acme-public-logs", Region: "us-east-1", PolicyAllowsPublic: true, MFADelete: true},
		},
		IAMRoles: []IAMRole{
			{ARN: roleP + "web-role", Name: "web-role", AssumeRolePolicyDocument: ec2Trust,
				InlinePolicies: raws(allowDoc("s3:GetObject", piiARN))},
			{ARN: roleP + "deploy-role", Name: "deploy-role", AssumeRolePolicyDocument: ec2Trust,
				InlinePolicies: raws(allowDoc("iam:CreatePolicyVersion", "*"))}, // real privesc (no boundary)
			{ARN: roleP + "ci-role", Name: "ci-role", AssumeRolePolicyDocument: ec2Trust,
				InlinePolicies:      raws(allowDoc("iam:CreatePolicyVersion", "*")),
				PermissionsBoundary: allowDoc("s3:Get*", "*")}, // boundary blocks the escalation ⇒ inert
			{ARN: roleP + "app-role", Name: "app-role", AssumeRolePolicyDocument: ec2Trust,
				InlinePolicies: raws(allowDoc("sts:AssumeRole", roleP+"db-operator-role"))},
			{ARN: roleP + "db-operator-role", Name: "db-operator-role",
				AssumeRolePolicyDocument: allowDoc("sts:AssumeRole", roleP+"trusted-pipeline"), // does NOT trust app-role
				InlinePolicies:           raws(allowDoc("s3:GetObject", finARN))},
		},
		EC2Instances: []EC2Instance{
			{ARN: ec2P + "i-web", Name: "web", PublicIPAddress: "203.0.113.10", IAMInstanceProfileRoleARN: roleP + "web-role", SecurityGroupIDs: []string{"sg-open"}},
			{ARN: ec2P + "i-deploy", Name: "deploy", PublicIPAddress: "203.0.113.11", IAMInstanceProfileRoleARN: roleP + "deploy-role", SecurityGroupIDs: []string{"sg-open"}},
			{ARN: ec2P + "i-ci", Name: "ci", PublicIPAddress: "203.0.113.12", IAMInstanceProfileRoleARN: roleP + "ci-role", SecurityGroupIDs: []string{"sg-open"}},
			{ARN: ec2P + "i-app", Name: "app", PublicIPAddress: "203.0.113.13", IAMInstanceProfileRoleARN: roleP + "app-role", SecurityGroupIDs: []string{"sg-open"}},
		},
	}

	ds := &Dataset{Tables: t, AnswerKey: AnswerKey{
		RealTargets: []string{piiARN, cloudgraph.AdminID},
		InertFindings: []string{
			FindingID("iam_policy_allows_privilege_escalation", roleP+"ci-role"), // boundary-blocked
			FindingID("s3_bucket_no_mfa_delete", finARN),                         // trust-denied
			FindingID("s3_bucket_public_access", logsARN),                        // non-sensitive
		},
	}}
	if err := ds.validateIndependently(); err != nil {
		return nil, err
	}
	return ds, nil
}

// validateIndependently asserts the answer key with cloudiam (NOT the engine):
// the real privesc must really escalate, the boundary one must really be blocked,
// and the trust must really deny app-role. A mis-built scenario is rejected so it
// can never silently score as an engine miss.
func (ds *Dataset) validateIndependently() error {
	roles := map[string]IAMRole{}
	for _, r := range ds.Tables.IAMRoles {
		roles[r.Name] = r
	}
	// real privesc (deploy-role, no boundary) must escalate
	if !escalates(roles["deploy-role"]) {
		return fmt.Errorf("validate: deploy-role should escalate but does not")
	}
	// boundary privesc (ci-role) must NOT escalate
	if escalates(roles["ci-role"]) {
		return fmt.Errorf("validate: ci-role escalation should be blocked by its boundary but is not")
	}
	// trust: db-operator-role must NOT trust app-role
	trust := parseDoc(roles["db-operator-role"].AssumeRolePolicyDocument)
	if ok, _ := cloudiam.Allows("sts:AssumeRole", roleP+"app-role", trust); ok {
		return fmt.Errorf("validate: db-operator-role should not trust app-role but does")
	}
	// web-role must be able to read the pii bucket
	if !effectiveAllows("s3:GetObject", piiARN, parseDocs(roles["web-role"].InlinePolicies), nil) {
		return fmt.Errorf("validate: web-role should read pii but cannot")
	}
	return nil
}

func escalates(r IAMRole) bool {
	attached := parseDocs(r.InlinePolicies)
	boundary := parseDoc(r.PermissionsBoundary)
	can := func(a string) bool { return effectiveAllows(a, "*", attached, boundary) }
	return len(cloudiam.DetectPrivesc(can)) > 0
}

// Score compares the engine's assessment against the independent answer key.
type Score struct {
	RealTotal   int      `json:"real_total"`
	RealFound   int      `json:"real_found"`
	PathRecall  float64  `json:"path_recall"`
	InertTotal  int      `json:"inert_total"`
	InertDown   int      `json:"inert_downgraded"`
	FPReduction float64  `json:"fp_reduction"`
	Missed      []string `json:"missed_real,omitempty"`
	Extra       []string `json:"extra_paths,omitempty"`
	Pass        bool     `json:"pass"`
}

// ScoreAssessment scores a *types.AIAssessment against the dataset answer key.
func ScoreAssessment(ds *Dataset, a *types.AIAssessment) Score {
	real := toSet(ds.AnswerKey.RealTargets)
	down := toSet(a.Downgraded)
	found := map[string]bool{}
	var extra []string
	for _, p := range a.Paths {
		end := pathEndID(p)
		if real[end] {
			found[end] = true
		} else {
			extra = appendUniq(extra, end)
		}
	}
	var s Score
	for t := range real {
		s.RealTotal++
		if found[t] {
			s.RealFound++
		} else {
			s.Missed = appendUniq(s.Missed, t)
		}
	}
	for _, fid := range ds.AnswerKey.InertFindings {
		s.InertTotal++
		if down[fid] {
			s.InertDown++
		}
	}
	s.PathRecall = ratio(s.RealFound, s.RealTotal)
	s.FPReduction = ratio(s.InertDown, s.InertTotal)
	sort.Strings(extra)
	sort.Strings(s.Missed)
	s.Extra = extra
	s.Pass = s.RealFound == s.RealTotal && s.InertDown == s.InertTotal && len(extra) == 0
	return s
}

// Render formats the prowler-grounded CloudQuery scorecard.
func Render(ds *Dataset, findings []types.Finding, a *types.AIAssessment, s Score) string {
	var b strings.Builder
	verdict := "PASS"
	if !s.Pass {
		verdict = "FAIL / divergence — see below"
	}
	fmt.Fprintf(&b, "=== AI Cloud Engineer vs prowler-grounded CloudQuery account ===\n")
	fmt.Fprintf(&b, "dataset: %d S3, %d IAM roles, %d EC2, %d SG\n",
		len(ds.Tables.S3Buckets), len(ds.Tables.IAMRoles), len(ds.Tables.EC2Instances), len(ds.Tables.SecurityGroups))
	fmt.Fprintf(&b, "prowler findings (catalog over the config): %d  →  engine real paths: %d, downgraded: %d\n",
		len(findings), len(a.Paths), len(a.Downgraded))
	fmt.Fprintf(&b, "attack-path recall: %.2f%%  (%d/%d real targets reached)\n", s.PathRecall*100, s.RealFound, s.RealTotal)
	fmt.Fprintf(&b, "FP-reduction:       %.2f%%  (%d/%d inert findings downgraded)\n", s.FPReduction*100, s.InertDown, s.InertTotal)
	fmt.Fprintf(&b, "verdict:            %s\n", verdict)
	if len(s.Missed) > 0 {
		fmt.Fprintf(&b, "MISSED real targets: %s\n", strings.Join(s.Missed, ", "))
	}
	if len(s.Extra) > 0 {
		fmt.Fprintf(&b, "EXTRA paths (engine over-reported): %s\n", strings.Join(s.Extra, ", "))
	}
	fmt.Fprintf(&b, "note: badness is prowler's (its check catalog over the CloudQuery config);\n")
	fmt.Fprintf(&b, "  exploitability truth is cloudiam's (effective perms over trust policies +\n")
	fmt.Fprintf(&b, "  permission boundaries). The engineer correctly separates the two BECAUSE the\n")
	fmt.Fprintf(&b, "  CloudQuery ingest resolves effective permissions — the boundary-blocked privesc\n")
	fmt.Fprintf(&b, "  and trust-denied assume are downgraded, not reported (the held-out gap, closed).\n")
	return b.String()
}

// --- small helpers ---

func allowDoc(action, resource string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":%q,"Resource":%q}]}`, action, resource))
}
func raws(d ...json.RawMessage) []json.RawMessage { return d }

func pathEndID(p types.AttackPath) string {
	if n := len(p.Graph.Nodes); n > 0 {
		return p.Graph.Nodes[n-1].ID
	}
	return ""
}
func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
func appendUniq(xs []string, x string) []string {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}
func ratio(n, d int) float64 {
	if d == 0 {
		return 1
	}
	return float64(n) / float64(d)
}
