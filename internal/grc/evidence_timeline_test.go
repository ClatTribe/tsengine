package grc

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// seedControl sets one control's state directly (bypassing the finding path) so a test can shape a
// specific met/gap posture for a framework.
func seedControl(t *testing.T, g *GRC, tenant, framework, control, state string) {
	t.Helper()
	if err := g.Store.UpsertControlState(context.Background(), platform.ControlState{
		TenantID: tenant, Framework: framework, ControlID: control, State: state,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestCaptureEvidenceSnapshot_ChangeAndHeartbeat locks the two gates that keep the continuous-evidence
// timeline meaningful without bloat: (1) an UNCHANGED posture within the heartbeat window is SKIPPED;
// (2) a posture CHANGE captures immediately; (3) an unchanged posture PAST the heartbeat captures again
// (the periodic "still holds" proof). Grounded: an unassessed framework captures nothing.
func TestCaptureEvidenceSnapshot_ChangeAndHeartbeat(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	g := &GRC{Store: store.NewMemory(), Now: func() time.Time { return clock }}
	const tenant, fw = "t1", FrameworkSOC2
	day := 24 * time.Hour

	// unassessed framework → nothing to attest.
	if _, captured, err := g.CaptureEvidenceSnapshot(ctx, tenant, fw, day); err != nil || captured {
		t.Fatalf("unassessed framework must capture nothing, captured=%v err=%v", captured, err)
	}

	// assess two controls, both met → first capture records a fully-met point.
	seedControl(t, g, tenant, fw, "CC6.1", platform.ControlMet)
	seedControl(t, g, tenant, fw, "CC7.1", platform.ControlMet)
	snap, captured, err := g.CaptureEvidenceSnapshot(ctx, tenant, fw, day)
	if err != nil || !captured {
		t.Fatalf("first capture must record a snapshot, captured=%v err=%v", captured, err)
	}
	if !snap.FullyMet || snap.MetControls != 2 || snap.GapControls != 0 || snap.TotalControls != 2 {
		t.Fatalf("first snapshot posture wrong: %+v", snap)
	}

	// same posture, 1h later, within the heartbeat window → SKIP (no bloat).
	clock = clock.Add(time.Hour)
	if _, captured, _ := g.CaptureEvidenceSnapshot(ctx, tenant, fw, day); captured {
		t.Error("an unchanged posture within the heartbeat window must be skipped")
	}

	// a control drifts to a gap → capture immediately, even within the window.
	seedControl(t, g, tenant, fw, "CC7.1", platform.ControlGap)
	changed, captured, _ := g.CaptureEvidenceSnapshot(ctx, tenant, fw, day)
	if !captured {
		t.Fatal("a posture change must capture immediately regardless of the interval")
	}
	if changed.FullyMet || changed.GapControls != 1 {
		t.Fatalf("changed snapshot should show 1 gap, not fully-met: %+v", changed)
	}

	// unchanged posture but the heartbeat window has elapsed → capture again (the "still holds" proof).
	clock = clock.Add(2 * day)
	if _, captured, _ := g.CaptureEvidenceSnapshot(ctx, tenant, fw, day); !captured {
		t.Error("an unchanged posture past the heartbeat window must capture again")
	}
}

// TestEvidenceTimeline_Continuity: the timeline reads back oldest→newest with a grounded continuity
// summary — fully-met ratio + the Continuous bit (every captured snapshot fully met). A window that had a
// gap at any captured point is NOT continuous.
func TestEvidenceTimeline_Continuity(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	g := &GRC{Store: store.NewMemory(), Now: func() time.Time { return clock }}
	const tenant, fw = "t1", FrameworkSOC2

	seedControl(t, g, tenant, fw, "CC6.1", platform.ControlMet)
	// day 1: fully met.
	if _, ok, _ := g.CaptureEvidenceSnapshot(ctx, tenant, fw, 0); !ok {
		t.Fatal("day-1 capture failed")
	}
	// day 2: a gap appears.
	clock = clock.Add(24 * time.Hour)
	seedControl(t, g, tenant, fw, "CC6.1", platform.ControlGap)
	if _, ok, _ := g.CaptureEvidenceSnapshot(ctx, tenant, fw, 0); !ok {
		t.Fatal("day-2 capture failed")
	}

	tl, err := g.EvidenceTimeline(ctx, tenant, fw)
	if err != nil {
		t.Fatal(err)
	}
	if tl.Count != 2 || len(tl.Snapshots) != 2 {
		t.Fatalf("want 2 snapshots, got %d", tl.Count)
	}
	// oldest-first ordering.
	if !tl.Snapshots[0].CapturedAt.Before(tl.Snapshots[1].CapturedAt) {
		t.Error("timeline must be oldest-first")
	}
	// one of two fully met → 0.5, and NOT continuous (a gap appeared in the window).
	if tl.FullyMetRatio != 0.5 {
		t.Errorf("want fully-met ratio 0.5, got %v", tl.FullyMetRatio)
	}
	if tl.Continuous {
		t.Error("a window with a gap at any captured point must NOT read as continuous")
	}
	if tl.FirstCapturedAt == nil || tl.LastCapturedAt == nil {
		t.Error("first/last captured timestamps must be set")
	}

	// a different framework the tenant never assessed → empty timeline, never a fabricated "continuous".
	empty, _ := g.EvidenceTimeline(ctx, tenant, FrameworkPCI)
	if empty.Count != 0 || empty.Continuous {
		t.Errorf("an un-monitored framework must be an empty, non-continuous timeline, got %+v", empty)
	}
}
