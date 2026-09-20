package bench

import (
	"context"
	"testing"
	"time"
)

type finishLLM struct{ n int }

func (f *finishLLM) Generate(_ context.Context, _ string) (string, error) {
	f.n++
	return `{"thought":"done","tool":"finish","args":{"summary":"none"}}`, nil
}

// TestCrossSurfaceAgentTerminates separates "the bench is broken" from "the model is slow" — a
// distinction that cost real time to make by hand. With a model that finishes immediately the whole
// head-to-head must complete in milliseconds; if it does not, the bug is in the bench and no amount
// of waiting on a live proxy will reveal it. Measured: 617µs, 2 model calls, discriminating.
//
// This exists because the bench's first live run returned an EMPTY log after 900s and I could not
// tell, without this, whether it had hung or was merely slow on a free model. It was slow.
func TestCrossSurfaceAgentTerminates(t *testing.T) {
	fx := LeakedKeyToCloudCrown()
	llm := &finishLLM{}
	done := make(chan CrossSurfaceAgentResult, 1)
	start := time.Now()
	go func() { done <- RunCrossSurfaceAgent(context.Background(), fx, llm, 4) }()
	select {
	case r := <-done:
		t.Logf("completed in %v after %d model calls; cloud_only.chain=%v estate.chain=%v discriminating=%v",
			time.Since(start), llm.n, r.CloudOnly.ReportedChain, r.Estate.ReportedChain, r.Discriminating)
	case <-time.After(20 * time.Second):
		t.Fatalf("HUNG: no result in 20s with a model that finishes immediately (%d calls made) — the bug is in the bench", llm.n)
	}
}
