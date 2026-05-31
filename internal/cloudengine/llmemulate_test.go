package cloudengine

import (
	"context"
	"testing"
)

// scriptLLM returns a canned response — lets CI exercise the emulate parse/score
// path with no API key (the real Gemini client plugs into the same LLM iface).
type scriptLLM struct{ resp string }

func (m scriptLLM) Generate(_ context.Context, _ string) (string, error) { return m.resp, nil }

// A small but complete emulated account: one genuinely-reachable real path
// (internet → web ec2 → role → sensitive bucket), one inert decoy (a sensitive
// bucket whose assume edge is gated by a runtime condition), and a corroborating
// + an inert prowler finding. Mirrors the shape the external model emits.
const cannedAccount = `{
  "inventory": {
    "account_id": "emu-acct", "provider": "aws",
    "resources": [
      {"id": "internet", "kind": "network", "name": "internet"},
      {"id": "web-ec2", "kind": "resource", "type": "AWS::EC2::Instance", "name": "web", "public": true},
      {"id": "web-role", "kind": "principal", "type": "AWS::IAM::Role", "name": "web-role"},
      {"id": "pii", "kind": "data", "type": "AWS::S3::Bucket", "name": "pii", "sensitive": "high"},
      {"id": "dpub", "kind": "resource", "type": "AWS::EC2::Instance", "name": "dpub", "public": true},
      {"id": "drole", "kind": "principal", "type": "AWS::IAM::Role", "name": "drole"},
      {"id": "dsecret", "kind": "data", "type": "AWS::S3::Bucket", "name": "dsecret", "sensitive": "high"}
    ],
    "reaches": [
      {"from": "internet", "to": "web-ec2"},
      {"from": "internet", "to": "dpub"}
    ],
    "runs_as": [
      {"compute": "web-ec2", "principal": "web-role"},
      {"compute": "dpub", "principal": "drole"}
    ],
    "grants": [
      {"principal": "web-role", "resource": "pii"},
      {"principal": "drole", "resource": "dsecret", "condition": "aws:MultiFactorAuthPresent=true"}
    ]
  },
  "prowler": [
    {"id": "p-real", "resource": "pii", "check_id": "s3_bucket_public_access", "severity": "high"},
    {"id": "p-inert", "resource": "dsecret", "check_id": "s3_bucket_no_mfa_delete", "severity": "high"}
  ],
  "answer_key": {
    "real_targets": ["pii"],
    "inert_findings": [
      {"finding_id": "p-inert", "resource": "dsecret", "reason": "grant gated by MFA runtime condition"}
    ]
  }
}`

func TestEmulate_ParseIngestScore(t *testing.T) {
	acc, err := GenerateEmulated(context.Background(), scriptLLM{resp: cannedAccount}, 1, 1)
	if err != nil {
		t.Fatalf("GenerateEmulated: %v", err)
	}
	if len(acc.Prowler) != 2 {
		t.Fatalf("expected 2 prowler findings, got %d", len(acc.Prowler))
	}

	snap, err := acc.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot (ingest): %v", err)
	}
	a := Assess(snap, acc.Prowler, SnapshotOracle{}, Options{})
	s := ScoreEmulated(acc, a)

	if s.PathRecall != 1.0 {
		t.Errorf("recall = %.2f, want 1.0 (the real pii path must be found)", s.PathRecall)
	}
	if s.FPReduction != 1.0 {
		t.Errorf("FP-reduction = %.2f, want 1.0 (the MFA-gated decoy must be downgraded)", s.FPReduction)
	}
	if len(s.ExtraPaths) != 0 {
		t.Errorf("unexpected extra paths: %v", s.ExtraPaths)
	}
	if !s.Pass {
		t.Errorf("expected PASS on the canned account: %+v", s)
	}
}

// A malformed answer key (real_target not in the inventory) must be rejected, not
// silently scored as an engine miss.
func TestEmulate_RejectsMalformedKey(t *testing.T) {
	const bad = `{"inventory":{"provider":"aws","resources":[{"id":"a","kind":"data","sensitive":"high"}]},
	  "prowler":[],"answer_key":{"real_targets":["does-not-exist"],"inert_findings":[]}}`
	if _, err := GenerateEmulated(context.Background(), scriptLLM{resp: bad}, 1, 0); err == nil {
		t.Error("expected validation error for a real_target absent from the inventory")
	}
}
