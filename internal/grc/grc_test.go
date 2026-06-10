package grc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func findingWithCompliance() types.Finding {
	return types.Finding{
		ID: "f1", Title: "Public S3 bucket", Severity: types.SeverityHigh, Tool: "prowler",
		Compliance: &types.Compliance{
			SOC2:     []string{"CC6.1", "CC6.6"},
			ISO27001: []string{"A.8.1"},
		},
	}
}

func TestApply_FindingMarksControlsGapWithEvidence(t *testing.T) {
	g := &GRC{Store: store.NewMemory()}
	ctx := context.Background()

	if err := g.Apply(ctx, "t1", findingWithCompliance()); err != nil {
		t.Fatal(err)
	}

	soc2, _ := g.Posture(ctx, "t1", FrameworkSOC2)
	if len(soc2) != 2 {
		t.Fatalf("want 2 soc2 controls in gap, got %d", len(soc2))
	}
	// deterministic order (CC6.1 before CC6.6), gap state, finding cited as evidence
	if soc2[0].ControlID != "CC6.1" || soc2[0].State != platform.ControlGap {
		t.Errorf("control 0 wrong: %+v", soc2[0])
	}
	if len(soc2[0].EvidenceRefs) != 1 || soc2[0].EvidenceRefs[0] != "f1" {
		t.Errorf("control must cite the finding as evidence: %+v", soc2[0])
	}
	iso, _ := g.Posture(ctx, "t1", FrameworkISO27001)
	if len(iso) != 1 || iso[0].ControlID != "A.8.1" {
		t.Errorf("iso posture wrong: %+v", iso)
	}
}

func TestApply_NoComplianceIsNoop(t *testing.T) {
	g := &GRC{Store: store.NewMemory()}
	ctx := context.Background()
	if err := g.Apply(ctx, "t1", types.Finding{ID: "x", Severity: types.SeverityLow}); err != nil {
		t.Fatal(err)
	}
	if cs, _ := g.Posture(ctx, "t1", FrameworkSOC2); len(cs) != 0 {
		t.Errorf("a finding with no compliance mapping must assert nothing, got %d", len(cs))
	}
}

func TestApply_TenantIsolation(t *testing.T) {
	g := &GRC{Store: store.NewMemory()}
	ctx := context.Background()
	_ = g.Apply(ctx, "t1", findingWithCompliance())
	if cs, _ := g.Posture(ctx, "t2", FrameworkSOC2); len(cs) != 0 {
		t.Errorf("ISOLATION: t2 must see no control state, got %d", len(cs))
	}
}

func TestEvidencePack_SignVerifyAndTamper(t *testing.T) {
	g := &GRC{Store: store.NewMemory()}
	ctx := context.Background()
	_ = g.Apply(ctx, "t1", findingWithCompliance())

	pack, err := g.EvidencePack(ctx, "t1", FrameworkSOC2)
	if err != nil {
		t.Fatal(err)
	}
	if pack.GapCount != 2 || len(pack.Controls) != 2 {
		t.Fatalf("pack should reflect 2 gaps: %+v", pack)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := Sign(pack, "tsengine-grc-key", priv, pack.GeneratedAt); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pack, pub); err != nil {
		t.Fatalf("fresh pack should verify: %v", err)
	}

	// tampering a control state after signing must break verification
	pack.Controls[0].State = platform.ControlMet
	if Verify(pack, pub) == nil {
		t.Fatal("editing the pack after signing must break verification")
	}
}
