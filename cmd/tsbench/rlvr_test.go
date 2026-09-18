package main

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/rlvr"
)

// The built-in demo corpus must grade exactly as designed against the reference target: the
// vulnerable host proven, the patched host REJECTED (FP=0). This is a plumbing self-test — the
// reference target is deterministic, so the number proves the pipeline is wired, NOT an efficacy
// claim. It guards against the seed/spec path silently breaking (a HeuristicSpecGen regression, a
// predicate change) which would show here as an FP, an FN, or a drop.
func TestRLVRSelftestPipeline(t *testing.T) {
	eps := demoCorpus()
	if len(eps) != 2 {
		t.Fatalf("demo corpus should seed 2 episodes, got %d", len(eps))
	}
	_, conf := rlvr.Run(context.Background(), referenceProber{}, nil, nil, eps)
	if conf.FP != 0 {
		t.Fatalf("patched host produced a false positive — the verifier's cardinal sin: %+v", conf)
	}
	if conf.TP != 1 || conf.TN != 1 {
		t.Fatalf("want 1 TP + 1 TN, got %+v", conf)
	}
	if conf.Ungradeable != 0 {
		t.Fatalf("reference target should reach both hosts, got %d dropped", conf.Ungradeable)
	}
	if s, ok := conf.Specificity(); !ok || s != 1 {
		t.Fatalf("specificity want 1.0, got %v ok=%v", s, ok)
	}
}
