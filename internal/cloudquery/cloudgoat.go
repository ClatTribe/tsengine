package cloudquery

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func anyEnvSet(keys ...string) bool {
	for _, k := range keys {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

func binOnPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Tier-1 calibration against CloudGoat (Rhino Security Labs) — the fidelity
// anchor (CLAUDE.md §14, docs/design/cloud-engine-overfitting.md §4).
//
// THE POINT (vs the prior rungs): here the ground truth is NOT computed by
// cloudiam. It is the PUBLISHED pentest solution of a real, deployable
// intentionally-vulnerable AWS lab. A real attempt was performed and documented
// by the scenario authors and the community; we transcribe the scenario's state
// (faithfully, from CloudGoat's public Terraform) and assert the engineer finds
// the SAME compromise the documented walkthrough reaches. So cloudiam moves from
// being the oracle to being UNDER TEST — refereed by the human-validated path.
//
// FIDELITY LADDER (honest about what runs where):
//   - replay (this code, runs now): transcribed scenario state + documented
//     ground truth. Removes cloudiam from the ground truth; does not perform a
//     live attempt in-process.
//   - live (RunTier1Live, env-gated): deploy the real scenario with `cloudgoat`,
//     sync the live account with CloudQuery, and confirm with a real
//     pacu/aws-cli attempt. Needs AWS creds + the cloudgoat/cloudquery binaries —
//     out-of-band setup, so it is wired as an explicit extension point, not run
//     in CI.

// Tier1Scenario is one CloudGoat scenario: its transcribed CloudQuery state, the
// starting credentials the scenario hands the attacker, and the DOCUMENTED
// compromise its published solution reaches.
type Tier1Scenario struct {
	Name              string
	Source            string   // citation: CloudGoat scenario + solution
	DocumentedPath    string   // the published attack path, in prose
	Tables            *Tables  // transcribed from CloudGoat's public Terraform
	Compromised       []string // principal ARNs the scenario GIVES the attacker (starting creds)
	DocumentedTargets []string // node ids the published solution compromises (the must-find)
}

// Tier1Scenarios returns the transcribed CloudGoat scenarios.
func Tier1Scenarios() []Tier1Scenario {
	return []Tier1Scenario{cloudBreachS3(), iamPrivescByRollback()}
}

// cloud_breach_s3: an internet-facing EC2 (behind a spoofable "WAF") runs an
// instance-profile role that can read a secret S3 bucket holding cardholder data.
// Documented path: external → EC2 metadata → role creds → exfil the secret bucket.
// Source: github.com/RhinoSecurityLabs/cloudgoat scenarios/cloud_breach_s3.
func cloudBreachS3() Tier1Scenario {
	bucket := "arn:aws:s3:::cg-secret-s3-bucket-cardholder-data"
	role := "arn:aws:iam::000000000000:role/cg-banking-WAF-Role"
	ec2 := "arn:aws:ec2:us-east-1:000000000000:instance/i-cg-ec2-waf"
	t := &Tables{
		SecurityGroups: []SecurityGroup{{ID: "sg-cg-waf", Name: "cg-waf-sg", OpenIngressFromInternet: true}},
		S3Buckets: []S3Bucket{{
			ARN: bucket, Name: "cg-secret-s3-bucket-cardholder-data", Region: "us-east-1",
			BlockPublicACLs: true, BlockPublicPolicy: true, MFADelete: false,
			Tags: map[string]string{"classification": "pii"}, // cardholder data
		}},
		IAMRoles: []IAMRole{{
			ARN: role, Name: "cg-banking-WAF-Role",
			AssumeRolePolicyDocument: allowDoc("sts:AssumeRole", "ec2.amazonaws.com"),
			InlinePolicies:           raws(allowDoc("s3:GetObject", bucket)),
		}},
		EC2Instances: []EC2Instance{{
			ARN: ec2, Name: "cg-ec2-waf", PublicIPAddress: "203.0.113.50",
			IAMInstanceProfileRoleARN: role, SecurityGroupIDs: []string{"sg-cg-waf"},
		}},
	}
	return Tier1Scenario{
		Name:   "cloud_breach_s3",
		Source: "CloudGoat (Rhino Security Labs) scenarios/cloud_breach_s3",
		DocumentedPath: "external attacker bypasses the WAF (spoofed X-Forwarded-For) → hits EC2 instance " +
			"metadata → steals cg-banking-WAF-Role creds → exfiltrates the cardholder-data S3 bucket",
		Tables:            t,
		DocumentedTargets: []string{bucket},
	}
}

// iam_privesc_by_rollback: the IAM user `raynor` holds iam:SetDefaultPolicyVersion
// (+ Get/List policy versions) over a managed policy whose an earlier version
// granted admin. Documented path: raynor rolls the policy's default version back
// to the admin version → full account compromise.
// Source: github.com/RhinoSecurityLabs/cloudgoat scenarios/iam_privesc_by_rollback.
func iamPrivescByRollback() Tier1Scenario {
	raynor := "arn:aws:iam::000000000000:user/raynor"
	// The escalation primitive prowler/PMapper key on is iam:SetDefaultPolicyVersion
	// (rolling back to a prior admin version). Get/List are the recon actions.
	pol := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:SetDefaultPolicyVersion","iam:GetPolicyVersion","iam:ListPolicyVersions","iam:ListPolicies","iam:ListAttachedUserPolicies"],"Resource":"*"}]}`)
	t := &Tables{
		IAMUsers: []IAMUser{{ARN: raynor, Name: "raynor", InlinePolicies: raws(pol)}},
	}
	return Tier1Scenario{
		Name:   "iam_privesc_by_rollback",
		Source: "CloudGoat (Rhino Security Labs) scenarios/iam_privesc_by_rollback",
		DocumentedPath: "attacker holds raynor's access keys → enumerates policy versions → " +
			"iam:SetDefaultPolicyVersion rolls the attached policy back to its admin version → admin",
		Tables:            t,
		Compromised:       []string{raynor},
		DocumentedTargets: []string{cloudgraph.AdminID},
	}
}

// Tier1Result is the engine's outcome on one scenario vs the documented truth.
type Tier1Result struct {
	Name       string   `json:"name"`
	Source     string   `json:"source"`
	DocTargets []string `json:"documented_targets"`
	Found      []string `json:"found"`
	Missed     []string `json:"missed"`
	Extra      []string `json:"extra_paths,omitempty"`
	Pass       bool     `json:"pass"`
}

// RunTier1 ingests a scenario through the effective-permission CloudQuery adapter
// and asserts the engineer reaches the DOCUMENTED compromise (recall is the gate;
// extra paths are reported, since the published walkthrough may not enumerate
// every path). cloudiam is exercised by the engine but is NOT the referee.
func RunTier1(sc Tier1Scenario, maxHyp int) (Tier1Result, *types.AIAssessment) {
	findings := EvalProwler(sc.Tables)
	inv := ToInventory(sc.Tables)
	// The scenario hands the attacker starting credentials — model that premise as
	// internet reachability of those principals (a leaked/assumed-compromised key).
	for _, p := range sc.Compromised {
		inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: p})
	}
	snap := cloudgraph.Ingest(inv)
	a := cloudengine.Assess(snap, findings, cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: maxHyp})

	doc := map[string]bool{}
	for _, d := range sc.DocumentedTargets {
		doc[d] = true
	}
	reached := map[string]bool{}
	var extra []string
	for _, p := range a.Paths {
		end := pathEndID(p)
		if doc[end] {
			reached[end] = true
		} else {
			extra = appendUniq(extra, end)
		}
	}
	res := Tier1Result{Name: sc.Name, Source: sc.Source, DocTargets: sc.DocumentedTargets}
	for _, tgt := range sc.DocumentedTargets {
		if reached[tgt] {
			res.Found = appendUniq(res.Found, tgt)
		} else {
			res.Missed = appendUniq(res.Missed, tgt)
		}
	}
	sort.Strings(extra)
	res.Extra = extra
	res.Pass = len(res.Missed) == 0
	return res, a
}

// RunTier1Live is the final-rung extension point: deploy the scenario for real
// and let a live attempt establish the ground truth instead of the documented
// walkthrough. It deliberately does NOT shell out blindly — it requires AWS creds
// in the environment and the cloudgoat + cloudquery binaries on PATH, and returns
// a clear error when they're absent so the harness degrades to replay mode rather
// than pretending. Implementing the deploy→sync→confirm loop is tracked work; the
// signature is fixed here so callers and CI gate on it cleanly.
func RunTier1Live(_ Tier1Scenario) (Tier1Result, error) {
	missing := liveModePrereqs()
	if len(missing) > 0 {
		return Tier1Result{}, fmt.Errorf("cloudgoat live mode unavailable (needs %s); use replay mode",
			strings.Join(missing, ", "))
	}
	return Tier1Result{}, fmt.Errorf("cloudgoat live deploy→sync→confirm loop not yet implemented; replay mode is the runnable rung")
}

// liveModePrereqs reports which live-mode prerequisites are absent.
func liveModePrereqs() []string {
	var missing []string
	if !anyEnvSet("AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_ROLE_ARN") {
		missing = append(missing, "AWS credentials in env")
	}
	if !binOnPath("cloudgoat") {
		missing = append(missing, "cloudgoat binary")
	}
	if !binOnPath("cloudquery") {
		missing = append(missing, "cloudquery binary")
	}
	return missing
}

// RenderTier1 formats the calibration scorecard with the mandatory citation.
func RenderTier1(results []Tier1Result) string {
	var b strings.Builder
	pass, total := 0, len(results)
	fmt.Fprintf(&b, "=== AI Cloud Engineer — Tier-1 calibration vs CloudGoat (Rhino Security Labs) ===\n")
	fmt.Fprintf(&b, "ground truth = the scenarios' PUBLISHED pentest solutions (a real lab, real attempt,\n")
	fmt.Fprintf(&b, "  documented) — NOT cloudiam. cloudiam is under test here, refereed by that path.\n\n")
	for _, r := range results {
		verdict := "PASS"
		if r.Pass {
			pass++
		} else {
			verdict = "MISS"
		}
		fmt.Fprintf(&b, "[%s] %s  (%s)\n", verdict, r.Name, r.Source)
		if len(r.Missed) > 0 {
			fmt.Fprintf(&b, "  MISSED documented target(s): %s\n", strings.Join(r.Missed, ", "))
		} else {
			fmt.Fprintf(&b, "  reached documented compromise: %s\n", strings.Join(r.Found, ", "))
		}
		if len(r.Extra) > 0 {
			fmt.Fprintf(&b, "  also reported (not in the walkthrough): %s\n", strings.Join(r.Extra, ", "))
		}
	}
	fmt.Fprintf(&b, "\ncalibration: %d/%d scenarios matched the documented real-lab compromise.\n", pass, total)
	fmt.Fprintf(&b, "fidelity note: this is REPLAY mode (transcribed state + documented truth). The final\n")
	fmt.Fprintf(&b, "  rung — deploy with `cloudgoat`, sync live state with CloudQuery, confirm with a real\n")
	fmt.Fprintf(&b, "  pacu/aws-cli attempt — needs AWS creds + those binaries (out-of-band, see RunTier1Live).\n")
	return b.String()
}
