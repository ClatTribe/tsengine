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
		Canary:  canary,
	}, true
}

// AgentSpecGen adapts the pentester's D-agent proposer (pentest.LLMSpecGen — the exact model call
// the AI pentester makes in ModeDeep) into an rlvr arm, so the ablation grades the real proposer,
// not a stand-in. rlvr stays decoupled from any model package: it takes the pentest.SpecLLM
// interface, and the caller supplies the concrete LLM (a cloud key or a local/served tuned model
// via cloudengine.LLMFromEnv, which satisfies SpecLLM structurally).
//
// It deliberately wraps LLMSpecGen and NOT SpecGenFor. SpecGenFor is the production first-attempt
// generator and falls back to HeuristicSpecGen when the model declines — correct for the product
// (never leave a finding unproven for want of a proposal), but WRONG for an ablation: a fallback
// silently substitutes the substrate's spec, so the "model arm" could never score below substrate
// because on failure it IS substrate. That is an unfalsifiable number (§14.2 rule 5). The pure
// model arm lets a decline be a decline — RunArm grades it NotExploited — so the model's measured
// lift can be negative, which is the only way the comparison means anything.
func AgentSpecGen(ctx context.Context, llm pentest.SpecLLM) SpecGen {
	return func(f types.Finding, canary string) *pentest.DemoSpec {
		return pentest.LLMSpecGen(ctx, llm, f, canary)
	}
}

// ReSeed rebuilds an episode's Spec from its Finding using the given arm, preserving id / target /
// truth / canary — the canary especially, so a canary-bound spec's probes reproduce and a recorded
// cassette still matches. ok=false when the arm DECLINES to propose (no spec); the caller records
// that as a NotExploited without touching the prober, which is the correct grounded mapping: a
// proposer that produced no exploit proved nothing — a recall miss on a vulnerable target, a
// correct rejection on a patched one.
func ReSeed(ep Episode, gen SpecGen) (Episode, bool) {
	spec := gen(ep.Finding, ep.Canary)
	if spec == nil {
		return Episode{}, false
	}
	out := ep
	out.Spec = *spec
	return out, true
}

// RunArm re-seeds each episode through one arm's proposer and grades it. A declined proposal grades
// NotExploited (no prober call). Use this for the ablation: RunArm(substrate) vs RunArm(agent) over
// the SAME episodes and probers gives the model's measured lift, scored by the identical predicate.
func RunArm(ctx context.Context, prober, browser pentest.Prober, interactor pentest.Interactor, eps []Episode, gen SpecGen) ([]Graded, Confusion) {
	graded := make([]Graded, 0, len(eps))
	for _, ep := range eps {
		seeded, ok := ReSeed(ep, gen)
		if !ok {
			// The arm proposed nothing — proved nothing. Grade it a negative directly.
			graded = append(graded, Graded{Episode: ep, Verdict: NotExploited})
			continue
		}
		graded = append(graded, Grade(ctx, prober, browser, interactor, seeded))
	}
	return graded, Score(graded)
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
