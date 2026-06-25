package grc

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestStarterPolicies(t *testing.T) {
	now := time.Now()
	a := StarterPolicies("t1", now)
	b := StarterPolicies("t1", now)
	if len(a) != len(starterPolicies) || len(a) == 0 {
		t.Fatalf("expected the full starter set, got %d", len(a))
	}
	if a[0].ID != b[0].ID || a[0].ID != "policy-information-security-policy" {
		t.Fatalf("ids must be deterministic+stable, got %q vs %q", a[0].ID, b[0].ID)
	}
	for _, p := range a {
		if p.Status != platform.PolicyDraft || p.Version != 1 || p.TenantID != "t1" {
			t.Errorf("seeded policy should be draft v1 for the tenant, got %+v", p)
		}
	}
}

func TestSummarizeProgram(t *testing.T) {
	pols := []platform.Policy{
		{Status: platform.PolicyPublished, Acks: []platform.PolicyAck{{User: "a"}, {User: "b"}}}, // fully acked (team 2)
		{Status: platform.PolicyPublished, Acks: []platform.PolicyAck{{User: "a"}}},              // 1/2
		{Status: platform.PolicyDraft},
	}
	s := SummarizeProgram(pols, 2)
	if s.Total != 3 || s.Published != 2 || s.Draft != 1 {
		t.Fatalf("counts wrong: %+v", s)
	}
	if s.FullyAcked != 1 { // only the first published policy is acked by the whole team
		t.Errorf("fully_acked = %d, want 1", s.FullyAcked)
	}
	// coverage = total acks (3) / (published 2 × team 2 = 4) = 75%
	if s.AckCoveragePct != 75 {
		t.Errorf("coverage = %d, want 75", s.AckCoveragePct)
	}
}

func TestPolicyAckedBy(t *testing.T) {
	p := platform.Policy{Acks: []platform.PolicyAck{{User: "dana"}}}
	if !p.AckedBy("dana") || p.AckedBy("sam") {
		t.Error("AckedBy should be true only for users who acknowledged")
	}
}
