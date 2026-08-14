package platformapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudhistory"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func onsetDeps(t *testing.T, captures ...map[string]cloudhistory.ResourceState) (Deps, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "t1"
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutFinding(ctx, tid, types.Finding{
		ID: "f-1", RuleID: "prowler::s3-public", Severity: types.SeverityHigh,
		Title: "Bucket is public", Endpoint: "arn:aws:s3:::reports",
	}); err != nil {
		t.Fatal(err)
	}
	h := cloudhistory.NewMemStore()
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	for i, res := range captures {
		if _, err := h.Append(ctx, cloudhistory.Digest{
			TenantID: tid, CapturedAt: base.Add(time.Duration(i) * time.Hour), Resources: res,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return Deps{Store: st, CloudHistory: h}, tid
}

func incident() []platform.Incident {
	return []platform.Incident{{ID: "i-1", TenantID: "t1", FindingID: "f-1",
		Title: "Bucket is public", Status: platform.IncidentOpen}}
}

// THE POINT: "this bucket is public" becomes "this bucket became public at 10:00".
func TestOnset_NamesWhenTheStateChanged(t *testing.T) {
	d, tid := onsetDeps(t,
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::reports": {Type: "s3_bucket"}},
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::reports": {Type: "s3_bucket", Public: true}},
	)
	incs := incident()
	d.annotateOnset(context.Background(), tid, incs)

	if incs[0].Onset == nil {
		t.Fatal("no onset attached — the responder still cannot tell a change from a long-standing state")
	}
	if !strings.Contains(incs[0].Onset.What, "internet-facing") {
		t.Errorf("onset does not say what happened: %q", incs[0].Onset.What)
	}
	if incs[0].Onset.At.Hour() != 10 {
		t.Errorf("onset dated %v, want the 10:00 capture where it flipped", incs[0].Onset.At)
	}
}

// THE REFUSAL THAT MATTERS MOST: a resource that does not match must be left ALONE. Attaching the wrong
// change sends a responder down a false timeline, which is worse than sending them with nothing.
func TestOnset_UnrelatedChangeIsNotAttached(t *testing.T) {
	d, tid := onsetDeps(t,
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::other-bucket": {Type: "s3_bucket"}},
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::other-bucket": {Type: "s3_bucket", Public: true}},
	)
	incs := incident()
	d.annotateOnset(context.Background(), tid, incs)
	if incs[0].Onset != nil {
		t.Errorf("a DIFFERENT bucket's change was attached to this incident: %+v", incs[0].Onset)
	}
}

// The note must say we report when we first SAW it, not when it happened — those are different facts
// and a responder reconstructing a timeline must not conflate them.
func TestOnset_SaysItIsFirstObservedNotWhenItHappened(t *testing.T) {
	d, tid := onsetDeps(t,
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::reports": {Type: "s3_bucket"}},
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::reports": {Type: "s3_bucket", Public: true}},
	)
	incs := incident()
	d.annotateOnset(context.Background(), tid, incs)
	if incs[0].Onset == nil {
		t.Fatal("no onset")
	}
	if !strings.Contains(strings.ToUpper(incs[0].Onset.Note), "FIRST OBSERVED") {
		t.Errorf("the note does not distinguish observation from occurrence: %q", incs[0].Onset.Note)
	}
}

// Too little history must annotate NOTHING rather than guess. A single capture cannot show change.
func TestOnset_TooLittleHistoryAnnotatesNothing(t *testing.T) {
	d, tid := onsetDeps(t,
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::reports": {Type: "s3_bucket", Public: true}},
	)
	incs := incident()
	d.annotateOnset(context.Background(), tid, incs)
	if incs[0].Onset != nil {
		t.Errorf("annotated from a single capture — there is nothing to compare against: %+v", incs[0].Onset)
	}
}

// No history configured at all must be a silent no-op, never a crash and never an invented onset.
func TestOnset_NoHistoryIsASafeNoOp(t *testing.T) {
	incs := incident()
	Deps{}.annotateOnset(context.Background(), "t1", incs)
	if incs[0].Onset != nil {
		t.Error("invented an onset with no history store configured")
	}
}

// A resource that changed twice annotates with the MOST RECENT transition — the one the responder is
// looking at, not the first one we ever saw.
func TestOnset_MostRecentTransitionWins(t *testing.T) {
	d, tid := onsetDeps(t,
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::reports": {Type: "s3_bucket"}},
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::reports": {Type: "s3_bucket", Public: true}},
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::reports": {Type: "s3_bucket"}},
		map[string]cloudhistory.ResourceState{"arn:aws:s3:::reports": {Type: "s3_bucket", Public: true}},
	)
	incs := incident()
	d.annotateOnset(context.Background(), tid, incs)
	if incs[0].Onset == nil {
		t.Fatal("no onset")
	}
	if incs[0].Onset.At.Hour() != 12 {
		t.Errorf("onset dated %v — a resource that flapped must report its LATEST transition (12:00)",
			incs[0].Onset.At)
	}
}
