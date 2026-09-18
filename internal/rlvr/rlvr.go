// Package rlvr is the reward-predicate harness for RL-with-verifiable-rewards over the
// exploit-verification task: "given a finding and a model-proposed exploitation predicate,
// did exploitation ACTUALLY succeed against the live target, or is this a hallucination?"
//
// It exists because a tuned verifier model is only worth training if its reward signal is
// GROUNDED — a deterministic predicate that RAN, never another model's opinion (§10). The
// harness reuses the product's own disposer (pentest.DemoFromSpec + Demonstration.Proven):
// the model PROPOSES a DemoSpec, the deterministic predicate DISPOSES over the real probe
// responses. So the reward cannot be reward-hacked by "assert success" — the response bytes
// are fixed by the world, and the predicate the model named is executed against them.
//
// The load-bearing design decision is the THIRD verdict. A pass is Exploited, a fail is
// NotExploited, and a target we could not reach is Ungradeable — DROPPED, never counted as a
// negative. Folding an unreachable container into NotExploited would train the model that a
// timeout is safe, the exact "scanner reports clean on DB failure" false-confidence this
// codebase already got burned by (§12.3). Absence of observation is not evidence of a
// negative. The drop rate is COUNTED and reported so a corpus that is quietly failing to
// reach its targets is visible rather than silently inflating either class.
package rlvr

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Verdict is the grounded outcome of one episode. It is the RL reward for training AND the
// prediction compared against ground truth at eval; the two uses never share the reward.
type Verdict int

const (
	// Exploited: the model's proposed predicate HELD over the real responses. Reward +1.
	Exploited Verdict = iota
	// NotExploited: the predicate RAN and did not hold, OR the spec was ill-formed (an
	// unknown predicate / missing arg / no probes → DemoFromSpec returned nil). Both are a
	// negative the model is responsible for, so both earn reward 0. Distinguished from a
	// world we could not observe, below.
	NotExploited
	// Ungradeable: a probe could not reach the target (transport error / nil prober). We did
	// not observe the world, so we cannot grade the model — the episode is DROPPED. This is
	// §10's "we could not look", and keeping it out of NotExploited is what stops the corpus
	// teaching the model that unreachable == safe.
	Ungradeable
)

func (v Verdict) String() string {
	switch v {
	case Exploited:
		return "exploited"
	case NotExploited:
		return "not_exploited"
	default:
		return "ungradeable"
	}
}

// Reward is the RLVR training reward. Only a grounded Exploited earns signal; an Ungradeable
// episode must be filtered by the caller BEFORE reward assignment (Grade returns the verdict
// so the loop can drop it), never handed here as a 0 — a 0 is a real negative.
func (v Verdict) Reward() float64 {
	if v == Exploited {
		return 1
	}
	return 0
}

// Truth is the corpus's KNOWN answer for an episode's target — vulnerable or patched. It is
// used ONLY by the scorer to build the confusion matrix (does the judge reject fake
// exploits?), NEVER by Grade to compute the training reward. The reward is grounded in the
// live predicate; the label is grounded in the corpus. Keeping them separate is what makes
// the FP number falsifiable: the model is never trained against the same label it is scored on.
type Truth int

const (
	TruthUnknown    Truth = iota // no held-out label (a pure training episode)
	TruthVulnerable              // the corpus says this target IS exploitable
	TruthPatched                 // the corpus says this target is NOT (the FP-control half)
)

// Episode is one gradeable unit: a finding, the model's proposed exploitation spec (the
// output under grade), and — for eval only — the corpus ground truth. The Prober that
// observes the world is injected at Grade time (a live vulhub container, or a record/replay
// cache), never stored on the episode, so the same recorded episode grades identically
// offline in CI and online against a container.
type Episode struct {
	ID      string           `json:"id"`
	Target  string           `json:"target"`          // human ref: image tag / URL / CTF id
	Finding types.Finding    `json:"finding"`         // what was proposed exploitable (provenance)
	Spec    pentest.DemoSpec `json:"spec"`            // the model's proposed predicate (UNDER GRADE)
	Truth   Truth            `json:"truth,omitempty"` // eval label; TruthUnknown for train-only
}

// Graded is an episode plus what grading it observed — the verdict, the responses the
// predicate saw (so a failed episode can be threaded back into the next proposal, the OODA
// refine loop pentest already does), and whether it was dropped.
type Graded struct {
	Episode Episode               `json:"episode"`
	Verdict Verdict               `json:"verdict"`
	Results []pentest.ProbeResult `json:"results,omitempty"`
	Reward  float64               `json:"reward"`
}

// ErrUngradeable is returned alongside the Ungradeable verdict so a caller that wants to fail
// loud (rather than silently drop) can. Grade never returns it for a model-side negative.
var ErrUngradeable = errors.New("rlvr: target unreachable — episode ungradeable")

// Grade disposes one episode: it resolves the model's proposed spec to the deterministic
// demonstration, sends the probes through the injected prober, and runs the predicate over
// the real responses. It reuses the product's OWN primitives (DemoFromSpec, Demonstration.
// Proven) so the reward the model trains against is exactly the proof the product ships.
//
// The send loop is re-implemented here rather than calling pentest.runDemoProven for ONE
// reason: that helper collapses a transport error into "unproven" (correct for the product —
// an error is not a proof), but the RLVR reward needs the Exploited / NotExploited /
// Ungradeable three-way split, and a transport error is Ungradeable, not NotExploited. The
// predicate evaluation itself is unchanged — the same Demonstration.Proven.
func Grade(ctx context.Context, prober, browser pentest.Prober, interactor pentest.Interactor, ep Episode) Graded {
	g := Graded{Episode: ep}

	demo := pentest.DemoFromSpec(ep.Spec, interactor)
	if demo == nil || len(demo.Probes) == 0 {
		// Ill-formed proposal: unknown predicate, missing required arg, or no probes. This is
		// the MODEL's failure to produce a valid spec, not the world's — a real negative, so
		// reward 0, NOT a drop. DemoFromSpec is the same gate the live agent passes through.
		g.Verdict = NotExploited
		return g
	}

	send := prober
	if demo.Channel == "browser" {
		send = browser
	}
	if send == nil {
		g.Verdict = Ungradeable // the channel's prober is not wired — we cannot observe. Drop.
		return g
	}

	results := make([]pentest.ProbeResult, 0, len(demo.Probes))
	for _, p := range demo.Probes {
		res, err := send.Send(ctx, p)
		if err != nil {
			// We could not reach the target. Not a negative — an unobserved world. Drop it,
			// and carry what we did see so the caller can log the partial.
			g.Verdict = Ungradeable
			g.Results = results
			return g
		}
		results = append(results, res)
	}
	g.Results = results

	if demo.Proven(results) {
		g.Verdict = Exploited
		g.Reward = 1
		return g
	}
	g.Verdict = NotExploited
	return g
}

// WriteJSONL streams graded episodes as one JSON object per line — the training corpus format.
// Every episode is written, Ungradeable included, so the drop rate is auditable downstream; the
// train loop filters on Verdict, it does not rely on the file omitting drops.
func WriteJSONL(w io.Writer, gs []Graded) error {
	enc := json.NewEncoder(w)
	for i := range gs {
		if err := enc.Encode(gs[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReadJSONL reads a graded corpus back (for scoring a prior run without re-probing).
func ReadJSONL(r io.Reader) ([]Graded, error) {
	dec := json.NewDecoder(r)
	var out []Graded
	for {
		var g Graded
		if err := dec.Decode(&g); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
		out = append(out, g)
	}
}
