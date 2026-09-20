package runner

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/training"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Training is assessed on the CLOCK, not on a write: a completion lapses on its anniversary with no
// event at all, so a pass is the only thing that can notice.
func TestAssessTraining_StoresWhoOwesItAndStamps(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.ReplaceEmployees(ctx, "t1", "merge", []platform.Employee{
		{TenantID: "t1", Source: "merge", ID: "e1", Name: "Ada", WorkEmail: "ada@acme.io", Status: platform.EmploymentActive},
	})
	n := 0
	svc := &Service{Store: st, NewID: func() string { n++; return itoa(n) }}

	out, ran := svc.assessTraining(ctx, "t1")
	if !ran {
		t.Fatal("assessTraining did not run with a roster present")
	}
	if len(out) != 1 || out[0].RuleID != training.RuleOutstanding || out[0].Endpoint != "ada@acme.io" {
		t.Fatalf("findings = %+v", out)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) != 1 {
		t.Fatalf("stored %d findings, want 1", len(stored))
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if tn.PostureAssessed["training"].IsZero() {
		t.Error("the programme was assessed and not stamped — a fully-trained roster yields zero " +
			"findings, which without the stamp reads identically to never having looked")
	}
}

// THE WIRING THAT MATTERS. Storing the finding is not enough: a compliance control opens only
// because a real finding CITES it, and the per-pass sync paths do not get GRC.Apply for free the way
// the per-asset path does. Without the fold the issues list shows the gap while the compliance
// posture reads clean — and the questionnaire's training question answers Yes for a roster that has
// done nothing.
func TestAssessTraining_OpensTheComplianceGapNotJustTheFinding(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.ReplaceEmployees(ctx, "t1", "merge", []platform.Employee{
		{TenantID: "t1", Source: "merge", ID: "e1", WorkEmail: "ada@acme.io", Status: platform.EmploymentActive},
	})
	n := 0
	svc := &Service{Store: st, NewID: func() string { n++; return itoa(n) }, GRC: &grc.GRC{Store: st}}

	if _, ran := svc.assessTraining(ctx, "t1"); !ran {
		t.Fatal("did not run")
	}
	states, err := st.Posture(ctx, "t1", "soc2")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, cs := range states {
		if cs.ControlID == "CC1.4" && cs.State == platform.ControlGap {
			found = true
		}
	}
	if !found {
		t.Error("SOC 2 CC1.4 did not open as a gap. The finding was stored but never folded into the " +
			"compliance system-of-record, so the posture reads clean for a workforce that has had no " +
			"training at all.")
	}
}

// An EMPTY roster returns false. That bool is what stops the questionnaire answering "Yes" for a
// company whose workforce we cannot see: nothing found and nothing to look at are different claims.
func TestAssessTraining_NoRosterIsNotCoverage(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	svc := &Service{Store: st, NewID: func() string { return "x" }}

	out, ran := svc.assessTraining(ctx, "t1")
	if ran {
		t.Error("an empty roster was reported as an assessed programme — the training question would " +
			"then answer Yes for a company whose people we cannot see")
	}
	if len(out) != 0 {
		t.Errorf("findings invented over an empty roster: %+v", out)
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if !tn.PostureAssessed["training"].IsZero() {
		t.Error("stamped as assessed with nobody on the roster")
	}
}

// A current roster produces nothing AND still counts as assessed — the mirror of the case above, and
// the one a false-compliant fix would break in the other direction.
func TestAssessTraining_ACurrentRosterIsCleanAndStillCounted(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.ReplaceEmployees(ctx, "t1", "merge", []platform.Employee{
		{TenantID: "t1", Source: "merge", ID: "e1", WorkEmail: "ada@acme.io", Status: platform.EmploymentActive},
	})
	for _, m := range training.Default().Modules {
		c, err := training.NewCompletion("ada@acme.io", m.ID, training.TierDelivered, "", "", "", time.Now(), training.Default())
		if err != nil {
			t.Fatal(err)
		}
		c.TenantID = "t1"
		if err := st.PutTrainingCompletion(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	svc := &Service{Store: st, NewID: func() string { return "x" }}

	out, ran := svc.assessTraining(ctx, "t1")
	if !ran {
		t.Fatal("a current roster was not counted as assessed")
	}
	if len(out) != 0 {
		t.Fatalf("a fully-trained roster produced findings: %+v", out)
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if tn.PostureAssessed["training"].IsZero() {
		t.Error("not stamped — zero findings and never looking must not read the same")
	}
}
