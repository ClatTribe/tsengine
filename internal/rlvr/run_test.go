package rlvr

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// fakeLLM is a scripted pentest.SpecLLM. "not json" models a model that declines / errors / returns
// an unparseable proposal.
type fakeLLM struct{ out string }

func (f fakeLLM) Generate(_ context.Context, _ string) (string, error) { return f.out, nil }

func sstiFinding() types.Finding {
	return types.Finding{Title: "Server-Side Template Injection", CWE: []string{"CWE-1336"}, Endpoint: "http://app/r?tpl=x"}
}

// The load-bearing falsifiability guard: the model arm must NOT fall back to the heuristic. If it
// did, "model" could never score below "substrate" (on failure it would BE substrate), and the
// ablation number would be meaningless. So a declining model yields NO spec, where substrate yields
// one for the same finding.
func TestAgentSpecGen_NoHeuristicFallback(t *testing.T) {
	f := sstiFinding()
	if SubstrateSpecGen()(f, "c") == nil {
		t.Fatal("substrate must propose a spec for an SSTI finding (guards the fixture)")
	}
	gen := AgentSpecGen(context.Background(), fakeLLM{out: "not a valid spec"})
	if gen(f, "c") != nil {
		t.Fatal("model arm fell back to heuristic — a declining model must yield no spec, or the ablation is unfalsifiable")
	}
}

// RunArm maps a declined proposal to NotExploited without touching the prober, and scores it
// correctly: a decline on a vulnerable finding is a recall miss (FN), never a drop.
func TestRunArm_DeclineIsNegativeNotDrop(t *testing.T) {
	declines := SpecGen(func(types.Finding, string) *pentest.DemoSpec { return nil })
	eps := []Episode{{ID: "v", Finding: sstiFinding(), Truth: TruthVulnerable, Canary: "c"}}
	graded, conf := RunArm(context.Background(), fakeProber{}, nil, nil, eps, declines)
	if graded[0].Verdict != NotExploited {
		t.Fatalf("declined proposal must grade NotExploited, got %s", graded[0].Verdict)
	}
	if conf.FN != 1 || conf.Ungradeable != 0 {
		t.Fatalf("decline on vulnerable → FN, not a drop: %+v", conf)
	}
}

// RunArm through the substrate arm reproduces the recorded probes (canary preserved), so a cassette
// recorded once still matches on re-seed — the property that lets score --arm substrate replay.
func TestRunArm_SubstrateReSeedIsStable(t *testing.T) {
	f := sstiFinding()
	ep := Episode{ID: "v", Finding: f, Truth: TruthVulnerable, Canary: "cx-v"}
	// Record the substrate probes once.
	rec := NewRecorder(referenceSSTI{})
	_, _ = RunArm(context.Background(), rec, nil, nil, []Episode{ep}, SubstrateSpecGen())
	// Re-seed + replay: same canary → same probes → cassette hit → same verdict.
	_, conf := RunArm(context.Background(), NewReplayer(rec.Cassette()), nil, nil, []Episode{ep}, SubstrateSpecGen())
	if conf.TP != 1 || conf.Ungradeable != 0 {
		t.Fatalf("substrate re-seed must replay stably: %+v", conf)
	}
}

// referenceSSTI models a vulnerable SSTI host for the re-seed test (evaluates the injected product).
type referenceSSTI struct{}

func (referenceSSTI) Send(_ context.Context, _ pentest.Probe) (pentest.ProbeResult, error) {
	return pentest.ProbeResult{Status: 200, Body: "rendered: 1022117"}, nil
}
