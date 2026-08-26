package orchestrator

import (
	"context"
	"testing"
)

func TestTrace_ChainLinksAndDrains(t *testing.T) {
	ctx, tr := NewTrace(context.Background())
	if tr == nil {
		t.Fatal("NewTrace must return a collector")
	}
	tr.Add("detection", "3 anchors fired", "model-x", 0, 0, "ok")
	tr.Add("sweep", "planned=12 ran=12", "model-x", 4500, 350, "ok")

	recs := tr.Records()
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if recs[0].PrevHash != "" {
		t.Error("the first record must chain from empty")
	}
	if recs[1].PrevHash != recs[0].Hash {
		t.Errorf("record 2 must chain from record 1's hash")
	}
	if recs[1].Hash == "" || recs[1].Hash == recs[0].Hash {
		t.Error("each record must carry its own chain hash")
	}

	// Draining via context must return the same collector's records.
	got := TraceFrom(ctx)
	if got == nil || len(got.Records()) != 2 {
		t.Fatal("TraceFrom must return the attached collector")
	}
}

func TestTraceFrom_NilWhenNotAttached(t *testing.T) {
	if tr := TraceFrom(context.Background()); tr != nil {
		t.Fatal("a plain context must yield nil — no trace, not an empty one")
	}
}

func TestTrace_NilReceiverSafe(t *testing.T) {
	var tr *Trace
	tr.Add("x", "y", "", 0, 0, "ok") // must not panic; fleet-style nil-safety
	if tr.Records() != nil {
		t.Error("records on nil collector must be nil")
	}
}
