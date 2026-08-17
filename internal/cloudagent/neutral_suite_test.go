package cloudagent

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudquery"
)

// A COMPLETE, scored agent run over a NEUTRAL suite (Bishop Fox IAM-Vulnerable +
// Rhino privesc taxonomy), driven by whatever LLM the env resolves — set
// LLM_BASE_URL to a relay/proxy for a frontier brain. Unlike the single-scenario
// neutral_agent_test, this sweeps every distinct REASONING shape the cloud engineer
// must handle and scores the aggregate:
//
//	positives (must find the documented crown-jewel path):
//	  single-hop privesc · passrole-to-compute · multi-hop assume→privesc ·
//	  data-exfil assume→read-PII · cross-account assume
//	negatives (FP-control — must record NOTHING; the effective-permission block
//	means there is no real path despite a scary-looking finding):
//	  permissions-boundary-blocked · SCP-blocked
//
// The negatives are the point: a recall-only agent that always records "reaches
// admin" scores 100% on the positives and FAILS here. Grounding (§10) is what makes
// the agent decline them, and this proves it end to end with a real model in the loop.
func TestAgentNeutralSuite(t *testing.T) {
	if os.Getenv("LLM_BASE_URL") == "" {
		t.Skip("set LLM_BASE_URL (relay/proxy) to run the neutral agent suite")
	}
	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		t.Skip("no LLM resolved from the environment")
	}

	for _, sc := range neutralAgentScenarios() {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			inv := cloudquery.ToInventory(sc.tables)
			// The scenario hands the attacker the principal's creds → model as internet reach.
			for _, p := range sc.compromised {
				inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: p})
			}
			snap := cloudgraph.Ingest(inv)
			findings := cloudquery.EvalProwler(sc.tables)

			rep, err := Investigate(context.Background(), llm, &Context{Snap: snap, Prowler: findings},
				Options{MaxIters: 16, MaxHyp: 20})
			if err != nil {
				t.Fatalf("investigation errored: %v", err)
			}

			hitTarget := false
			for _, is := range rep.Issues {
				for _, tgt := range sc.wantTargets {
					if is.Target == tgt {
						hitTarget = true
					}
				}
			}
			switch {
			case sc.mustNotRecord:
				if len(rep.Issues) != 0 {
					t.Errorf("[FALSE POSITIVE] %s recorded %d issue(s) on an effective-permission-blocked scenario; grounding should have declined it",
						sc.name, len(rep.Issues))
				} else {
					t.Logf("[correct — declined] %s: agent recorded nothing (block honoured) over %d call(s)", sc.name, rep.Calls)
				}
			default:
				if !hitTarget {
					t.Errorf("[MISS] %s: agent did not record the documented path to %v (issues=%d)", sc.name, sc.wantTargets, len(rep.Issues))
				} else {
					t.Logf("[correct — found] %s: agent reached %v over %d call(s)", sc.name, sc.wantTargets, rep.Calls)
				}
			}
		})
	}
}

type neutralScenario struct {
	name          string
	tables        *cloudquery.Tables
	compromised   []string // principals the scenario hands the attacker (internet-reachable)
	wantTargets   []string // documented crown jewels a positive must reach
	mustNotRecord bool     // true for the FP-control negatives
}

// --- inline policy builders (self-contained; the cloudquery _test helpers are not importable) ---

func adminPolicy() json.RawMessage {
	return json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
}
func allow(actions ...string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{
		{"Effect": "Allow", "Action": actions, "Resource": "*"}}})
	return b
}
func allowOn(action, resource string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{
		{"Effect": "Allow", "Action": action, "Resource": resource}}})
	return b
}
func trustsPrincipal(arn string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{
		{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]string{"AWS": arn}}}})
	return b
}
func trustsService(svc string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{
		{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]string{"Service": svc}}}})
	return b
}
func ivU(name string, pol json.RawMessage) cloudquery.IAMUser {
	return cloudquery.IAMUser{ARN: "arn:aws:iam::000000000000:user/" + name, Name: name, InlinePolicies: []json.RawMessage{pol}}
}

func neutralAgentScenarios() []neutralScenario {
	const acct = "arn:aws:iam::000000000000:"
	// shared admin role that trusts lambda — the passrole target
	lambdaAdmin := cloudquery.IAMRole{
		ARN: acct + "role/iv-admin-lambda", Name: "iv-admin-lambda",
		AssumeRolePolicyDocument: trustsService("lambda.amazonaws.com"),
		InlinePolicies:           []json.RawMessage{adminPolicy()},
	}

	// multi-hop: user assumes roleA, roleA holds a privesc primitive
	chainUser := acct + "user/iv-chain"
	roleA := cloudquery.IAMRole{
		ARN: acct + "role/iv-chain-roleA", Name: "iv-chain-roleA",
		AssumeRolePolicyDocument: trustsPrincipal(chainUser),
		InlinePolicies:           []json.RawMessage{allow("iam:AttachRolePolicy", "sts:AssumeRole")},
	}

	// data-exfil: user assumes a role that can read a sensitive bucket
	exfilUser := acct + "user/iv-exfil"
	pii := "arn:aws:s3:::iv-customer-pii"
	exfilRole := cloudquery.IAMRole{
		ARN: acct + "role/iv-exfil-role", Name: "iv-exfil-role",
		AssumeRolePolicyDocument: trustsPrincipal(exfilUser),
		InlinePolicies:           []json.RawMessage{allowOn("s3:GetObject", pii)},
	}
	piiBucket := cloudquery.S3Bucket{
		ARN: pii, Name: "iv-customer-pii", Region: "us-east-1",
		BlockPublicACLs: true, BlockPublicPolicy: true,
		Tags: map[string]string{"classification": "pii"},
	}

	// cross-account: userA (111) assumes admin roleB (222) whose trust allows 111
	userA := "arn:aws:iam::111111111111:user/attacker"
	roleB := cloudquery.IAMRole{
		ARN: "arn:aws:iam::222222222222:role/target", Name: "target",
		AssumeRolePolicyDocument: trustsPrincipal("arn:aws:iam::111111111111:root"),
		InlinePolicies:           []json.RawMessage{adminPolicy()},
	}

	// negative: boundary blocks the privesc action
	boundaryUser := cloudquery.IAMUser{
		ARN: acct + "user/iv-bnd", Name: "iv-bnd",
		InlinePolicies:      []json.RawMessage{allow("iam:AttachUserPolicy")},
		PermissionsBoundary: allow("s3:*"), // boundary grants only s3 — privesc is blocked
	}

	return []neutralScenario{
		{
			name:        "single_hop_attach_user_policy",
			tables:      &cloudquery.Tables{IAMUsers: []cloudquery.IAMUser{ivU("iv-attach", allow("iam:AttachUserPolicy"))}},
			compromised: []string{acct + "user/iv-attach"},
			wantTargets: []string{cloudgraph.AdminID},
		},
		{
			name: "passrole_lambda",
			tables: &cloudquery.Tables{
				IAMUsers: []cloudquery.IAMUser{ivU("iv-lambda", allow("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"))},
				IAMRoles: []cloudquery.IAMRole{lambdaAdmin},
			},
			compromised: []string{acct + "user/iv-lambda"},
			wantTargets: []string{cloudgraph.AdminID},
		},
		{
			name: "multi_hop_assume_then_privesc",
			tables: &cloudquery.Tables{
				IAMUsers: []cloudquery.IAMUser{{ARN: chainUser, Name: "iv-chain", InlinePolicies: []json.RawMessage{allow("sts:AssumeRole")}}},
				IAMRoles: []cloudquery.IAMRole{roleA},
			},
			compromised: []string{chainUser},
			wantTargets: []string{cloudgraph.AdminID},
		},
		{
			name: "data_exfil_assume_then_read_pii",
			tables: &cloudquery.Tables{
				IAMUsers:  []cloudquery.IAMUser{{ARN: exfilUser, Name: "iv-exfil", InlinePolicies: []json.RawMessage{allow("sts:AssumeRole")}}},
				IAMRoles:  []cloudquery.IAMRole{exfilRole},
				S3Buckets: []cloudquery.S3Bucket{piiBucket},
			},
			compromised: []string{exfilUser},
			wantTargets: []string{pii},
		},
		{
			name: "cross_account_assume",
			tables: &cloudquery.Tables{
				IAMUsers: []cloudquery.IAMUser{{ARN: userA, Name: "attacker", InlinePolicies: []json.RawMessage{allow("sts:AssumeRole")}}},
				IAMRoles: []cloudquery.IAMRole{roleB},
			},
			compromised: []string{userA},
			wantTargets: []string{cloudgraph.AdminID},
		},
		{
			name:          "fp_boundary_blocked",
			tables:        &cloudquery.Tables{IAMUsers: []cloudquery.IAMUser{boundaryUser}},
			compromised:   []string{acct + "user/iv-bnd"},
			mustNotRecord: true,
		},
		{
			name: "fp_scp_blocked",
			tables: &cloudquery.Tables{
				IAMUsers: []cloudquery.IAMUser{ivU("iv-scp", allow("iam:AttachUserPolicy"))},
				SCPs:     []json.RawMessage{allow("s3:*")}, // SCP grants only s3 — privesc blocked
			},
			compromised:   []string{acct + "user/iv-scp"},
			mustNotRecord: true,
		},
	}
}
