package detect

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// recordingResponder captures each RespondToIncidents call so a test can assert the engineer was (or
// was not) put on a batch.
type recordingResponder struct {
	calls   int
	lastLen int
}

func (r *recordingResponder) RespondToIncidents(_ context.Context, _ string, opened []platform.Incident) {
	r.calls++
	r.lastLen = len(opened)
}

// THE GAP THIS CLOSES: an event-driven ingest opens an incident, and the AI engineer is put on it —
// not left to the next scheduled scan.
func TestOpenFor_PutsTheResponderOnANewIncident(t *testing.T) {
	st := store.NewMemory()
	d := newDetector(st)
	r := &recordingResponder{}
	d.Responder = r

	res, err := d.OpenFor(context.Background(), "t1", []types.Finding{crit("identity::impossible-travel", "user@acme.com")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 1 {
		t.Fatalf("expected 1 incident opened, got %d", len(res.Opened))
	}
	if r.calls != 1 {
		t.Fatalf("responder called %d times, want 1 — the engineer was not put on the incident", r.calls)
	}
	if r.lastLen != 1 {
		t.Errorf("responder handed %d incidents, want the 1 that opened", r.lastLen)
	}
}

// It fires ONCE per batch with all opened incidents, not once per incident — a bulk event must not
// spawn N estate reviews.
func TestOpenFor_RespondsOncePerBatch(t *testing.T) {
	st := store.NewMemory()
	d := newDetector(st)
	r := &recordingResponder{}
	d.Responder = r

	batch := []types.Finding{
		crit("identity::impossible-travel", "a@acme.com"),
		crit("identity::mfa-removed", "b@acme.com"),
		crit("cloud::public-bucket", "arn:aws:s3:::x"),
	}
	res, _ := d.OpenFor(context.Background(), "t1", batch, nil)
	if len(res.Opened) != 3 {
		t.Fatalf("expected 3 opened, got %d", len(res.Opened))
	}
	if r.calls != 1 {
		t.Errorf("responder called %d times for one batch — a bulk event must trigger ONE review, not per-incident", r.calls)
	}
	if r.lastLen != 3 {
		t.Errorf("responder handed %d incidents, want all 3", r.lastLen)
	}
}

// Nothing new opened → the engineer is NOT spun up. Re-ingesting the same finding (idempotent, no new
// incident) must not re-review, or every duplicate event burns an LLM run.
func TestOpenFor_NoResponseWhenNothingOpened(t *testing.T) {
	st := store.NewMemory()
	d := newDetector(st)
	r := &recordingResponder{}
	d.Responder = r
	f := []types.Finding{crit("identity::impossible-travel", "user@acme.com")}

	if _, err := d.OpenFor(context.Background(), "t1", f, nil); err != nil {
		t.Fatal(err)
	}
	// Second ingest of the SAME finding opens no new incident (idempotent).
	res, _ := d.OpenFor(context.Background(), "t1", f, nil)
	if len(res.Opened) != 0 {
		t.Fatalf("second ingest opened %d incidents, expected 0 (idempotent)", len(res.Opened))
	}
	if r.calls != 1 {
		t.Errorf("responder fired %d times; a re-ingest that opens nothing must NOT re-review", r.calls)
	}
}

// THE ANTI-DOUBLE-REVIEW CONTRACT: the scan path (Reconcile) must NOT fire the responder, because it
// already triggers the engineer via AutoReviewAfterScan. Firing here too would review the same estate
// twice per scan.
func TestReconcile_DoesNotFireTheResponder(t *testing.T) {
	st := store.NewMemory()
	d := newDetector(st)
	r := &recordingResponder{}
	d.Responder = r

	res, err := d.Reconcile(context.Background(), "t1", []types.Finding{crit("cloud::public-bucket", "arn:aws:s3:::x")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 1 {
		t.Fatalf("expected 1 opened by the scan, got %d", len(res.Opened))
	}
	if r.calls != 0 {
		t.Errorf("Reconcile fired the responder %d times — the scan path already reviews via "+
			"AutoReviewAfterScan, so this would double-review", r.calls)
	}
}

// A nil responder is a no-op — a deployment without the AI engineer wired must ingest incidents exactly
// as before.
func TestOpenFor_NilResponderIsSafe(t *testing.T) {
	st := store.NewMemory()
	d := newDetector(st) // no Responder
	res, err := d.OpenFor(context.Background(), "t1", []types.Finding{crit("cloud::x", "arn:x")}, nil)
	if err != nil || len(res.Opened) != 1 {
		t.Fatalf("nil responder changed ingest behaviour: err=%v opened=%d", err, len(res.Opened))
	}
}
