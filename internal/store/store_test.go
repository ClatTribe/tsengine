package store

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestTenantIsolation(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()

	// two tenants, each with one finding + one connection
	_ = s.PutFinding(ctx, "t-a", types.Finding{ID: "f-a", Severity: types.SeverityHigh})
	_ = s.PutFinding(ctx, "t-b", types.Finding{ID: "f-b", Severity: types.SeverityLow})
	_ = s.PutConnection(ctx, platform.Connection{ID: "c-a", TenantID: "t-a", Kind: platform.ConnGitHub})
	_ = s.PutConnection(ctx, platform.Connection{ID: "c-b", TenantID: "t-b", Kind: platform.ConnAWS})

	fa, _ := s.ListFindings(ctx, "t-a", FindingFilter{})
	if len(fa) != 1 || fa[0].ID != "f-a" {
		t.Fatalf("tenant a must see only its finding, got %+v", fa)
	}
	// the security-critical assertion: tenant a NEVER sees tenant b's data
	for _, f := range fa {
		if f.ID == "f-b" {
			t.Fatal("ISOLATION BREACH: tenant a saw tenant b's finding")
		}
	}
	ca, _ := s.ListConnections(ctx, "t-a")
	if len(ca) != 1 || ca[0].Kind != platform.ConnGitHub {
		t.Fatalf("tenant a connections wrong: %+v", ca)
	}
	// an action under t-a must not be gettable under t-b
	_ = s.PutAction(ctx, platform.Action{ID: "act-1", TenantID: "t-a", Status: platform.ActProposed})
	if _, err := s.GetAction(ctx, "t-b", "act-1"); err != ErrNotFound {
		t.Fatalf("cross-tenant action read must be ErrNotFound, got %v", err)
	}
}

func TestFindingFilter(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	_ = s.PutFinding(ctx, "t", types.Finding{ID: "h", Severity: types.SeverityHigh, VerificationStatus: types.VerificationVerified})
	_ = s.PutFinding(ctx, "t", types.Finding{ID: "l", Severity: types.SeverityLow})

	hi, _ := s.ListFindings(ctx, "t", FindingFilter{Severity: types.SeverityHigh})
	if len(hi) != 1 || hi[0].ID != "h" {
		t.Errorf("severity filter wrong: %+v", hi)
	}
	ver, _ := s.ListFindings(ctx, "t", FindingFilter{Status: string(types.VerificationVerified)})
	if len(ver) != 1 || ver[0].ID != "h" {
		t.Errorf("status filter wrong: %+v", ver)
	}
}

func TestUpsertReplaces(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	_ = s.PutFinding(ctx, "t", types.Finding{ID: "f", Severity: types.SeverityLow})
	_ = s.PutFinding(ctx, "t", types.Finding{ID: "f", Severity: types.SeverityCritical}) // same id → replace
	got, _ := s.ListFindings(ctx, "t", FindingFilter{})
	if len(got) != 1 {
		t.Fatalf("upsert should not duplicate, got %d", len(got))
	}
	if got[0].Severity != types.SeverityCritical {
		t.Errorf("upsert should replace, got %v", got[0].Severity)
	}
}

func TestPendingApprovalsQueue(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	// a tier-2 action is gated; a tier-0 is not
	gated := platform.Action{ID: "a2", TenantID: "t", Tier: 2, Status: platform.ActPendingApproval}
	auto := platform.Action{ID: "a0", TenantID: "t", Tier: 0, Status: platform.ActApplied}
	if !gated.NeedsApproval() || auto.NeedsApproval() {
		t.Fatal("NeedsApproval gating wrong")
	}
	_ = s.PutAction(ctx, gated)
	_ = s.PutAction(ctx, auto)
	pend, _ := s.PendingApprovals(ctx, "t")
	if len(pend) != 1 || pend[0].ID != "a2" {
		t.Fatalf("only the gated action should be pending, got %+v", pend)
	}
}

func TestPostureSystemOfRecord(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	now := time.Now()
	_ = s.UpsertControlState(ctx, platform.ControlState{TenantID: "t", Framework: "soc2", ControlID: "CC6.1", State: platform.ControlGap, UpdatedAt: now})
	_ = s.UpsertControlState(ctx, platform.ControlState{TenantID: "t", Framework: "soc2", ControlID: "CC6.1", State: platform.ControlMet, EvidenceRefs: []string{"f-001"}, UpdatedAt: now}) // upsert
	_ = s.UpsertControlState(ctx, platform.ControlState{TenantID: "t", Framework: "iso27001", ControlID: "A.8.1", State: platform.ControlMet, UpdatedAt: now})

	soc2, _ := s.Posture(ctx, "t", "soc2")
	if len(soc2) != 1 || soc2[0].State != platform.ControlMet || len(soc2[0].EvidenceRefs) != 1 {
		t.Fatalf("soc2 posture wrong (upsert should collapse to 1 met w/ evidence): %+v", soc2)
	}
	iso, _ := s.Posture(ctx, "t", "iso27001")
	if len(iso) != 1 {
		t.Errorf("iso posture wrong: %+v", iso)
	}
}
