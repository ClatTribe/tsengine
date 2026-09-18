package rlvr

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// run.go seeds episodes from findings and grades a batch. An Episode needs a proposed DemoSpec —
// the thing under grade. Where does the proposal come from?
//
//   - SUBSTRATE arm (no model): pentest.HeuristicSpecGen — the deterministic spec generator. This
//     is what lets the harness run today at $0, and it is the ablation baseline the tuned verifier
//     must BEAT. A number that is only ever reported for the model arm is unfalsifiable; the
//     substrate arm is the control.
//   - MODEL arm: pentest.SpecGenFor(ctx, llm) or a captured model output. Same Episode shape, so
//     the two arms grade through the identical predicate and are directly comparable.
//
// SpecGen is that pluggable proposer. It mirrors pentest.SpecGenFor's signature exactly so the
// product's own generators drop in unchanged.
type SpecGen func(f types.Finding, canary string) *pentest.DemoSpec

// SubstrateSpecGen is the deterministic (no-model) proposer — the ablation control.
func SubstrateSpecGen() SpecGen {
	return func(f types.Finding, canary string) *pentest.DemoSpec {
		return pentest.HeuristicSpecGen(f, canary)
	}
}

// SeedEpisode builds one gradeable episode from a finding: it asks the proposer for a spec and, if
// one is produced, packages it with the finding and its ground-truth label. Returns ok=false when
// the proposer declines the finding (not its class) — a finding with no proposed exploit is not an
// episode, and inventing an empty one would seed the corpus with guaranteed negatives that teach
// nothing.
func SeedEpisode(id, target string, f types.Finding, truth Truth, canary string, gen SpecGen) (Episode, bool) {
	spec := gen(f, canary)
	if spec == nil {
		return Episode{}, false
	}
	return Episode{
		ID:      id,
		Target:  target,
		Finding: f,
		Spec:    *spec,
		Truth:   truth,
	}, true
}

// Run grades a batch of episodes through the same Grade path, returning the per-episode results
// and the confusion matrix in one pass. The prober is injected — a live Recorder-wrapped
// HTTPProber for a capture run, or a Replayer for CI/train re-scoring — so Run itself is unaware
// of whether it is online or offline. The ungradeable episodes are kept in the returned slice
// (so a caller can log which targets were unreachable) but excluded from the matrix by Score.
func Run(ctx context.Context, prober, browser pentest.Prober, interactor pentest.Interactor, eps []Episode) ([]Graded, Confusion) {
	graded := make([]Graded, 0, len(eps))
	for _, ep := range eps {
		graded = append(graded, Grade(ctx, prober, browser, interactor, ep))
	}
	return graded, Score(graded)
}
