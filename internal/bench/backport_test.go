package bench

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func insts() []BackportInstance {
	return []BackportInstance{
		{ID: "t1", Ecosystem: "pypi"},
		{ID: "t2", Ecosystem: "pypi"},
		{ID: "t3", Ecosystem: "npm"},
		{ID: "t4", Ecosystem: "maven"},
	}
}

func alwaysPatch(ctx context.Context, i BackportInstance) (map[string][]string, bool, error) {
	return map[string][]string{"a.py": {"patched"}}, true, nil
}

// THE KEY PROPERTY: the solver's own confidence is irrelevant — only the test
// oracle decides. A solver that "successfully" patches everything but whose
// patches fail the tests scores ZERO.
func TestScoreBackport_SolverCannotGradeItself(t *testing.T) {
	failAll := func(context.Context, BackportInstance, map[string][]string) (bool, string, error) {
		return false, "3 tests failed", nil
	}
	r := ScoreBackport(context.Background(), insts(), alwaysPatch, failAll)
	if r.Resolved != 0 || r.ResolveRate() != 0 {
		t.Fatalf("a confident solver whose tests fail must score 0, got %d/%d", r.Resolved, r.Total)
	}
	if r.Total != 4 {
		t.Errorf("total = %d, want 4", r.Total)
	}
}

// Per-ecosystem reporting, because a single number hides the per-language
// variance the benchmark exists to expose.
func TestScoreBackport_PerEcosystemSplit(t *testing.T) {
	// Only pypi tasks pass.
	runner := func(_ context.Context, i BackportInstance, _ map[string][]string) (bool, string, error) {
		return i.Ecosystem == "pypi", "", nil
	}
	r := ScoreBackport(context.Background(), insts(), alwaysPatch, runner)
	if r.Resolved != 2 {
		t.Fatalf("resolved = %d, want 2 (both pypi)", r.Resolved)
	}
	if got := r.ByEcosystem["pypi"].Rate(); got != 1 {
		t.Errorf("pypi rate = %v, want 1", got)
	}
	if got := r.ByEcosystem["npm"].Rate(); got != 0 {
		t.Errorf("npm rate = %v, want 0", got)
	}
	if r.ByEcosystem["maven"].Total != 1 {
		t.Errorf("maven total = %d, want 1", r.ByEcosystem["maven"].Total)
	}
	out := RenderBackport(r)
	for _, want := range []string{"pypi", "npm", "maven", "resolve rate"} {
		if !strings.Contains(out, want) {
			t.Errorf("render should mention %q:\n%s", want, out)
		}
	}
}

// An honest decline (our layer said needs_adaptation, nothing was produced) is
// unresolved but is NOT an error — and the two are reported separately so a
// broken harness can never look like a poor fix rate.
func TestScoreBackport_DeclineIsUnresolvedNotError(t *testing.T) {
	decline := func(context.Context, BackportInstance) (map[string][]string, bool, error) {
		return nil, false, nil
	}
	neverRun := func(context.Context, BackportInstance, map[string][]string) (bool, string, error) {
		t.Fatal("the runner must not be called when the solver declined")
		return false, "", nil
	}
	r := ScoreBackport(context.Background(), insts(), decline, neverRun)
	if r.Declined != 4 || r.Errors != 0 || r.Resolved != 0 {
		t.Fatalf("want 4 declined / 0 errors / 0 resolved, got %d/%d/%d", r.Declined, r.Errors, r.Resolved)
	}
}

func TestScoreBackport_ErrorsCountedSeparately(t *testing.T) {
	boom := func(context.Context, BackportInstance) (map[string][]string, bool, error) {
		return nil, false, errors.New("docker unavailable")
	}
	r := ScoreBackport(context.Background(), insts(), boom, nil)
	if r.Errors != 4 || r.Declined != 0 {
		t.Fatalf("want 4 errors / 0 declined, got %d/%d", r.Errors, r.Declined)
	}
	if r.ResolveRate() != 0 {
		t.Error("errors must not count as resolved")
	}
}

// A runner error is also unresolved + recorded (not a silent pass).
func TestScoreBackport_RunnerErrorIsRecorded(t *testing.T) {
	badRun := func(context.Context, BackportInstance, map[string][]string) (bool, string, error) {
		return false, "", errors.New("container exited 137")
	}
	r := ScoreBackport(context.Background(), insts(), alwaysPatch, badRun)
	if r.Errors != 4 || r.Resolved != 0 {
		t.Fatalf("want 4 errors / 0 resolved, got %d/%d", r.Errors, r.Resolved)
	}
	if r.Outcomes[0].Err == "" {
		t.Error("the outcome should carry the runner error")
	}
}

// A cancelled sweep reports what completed — partial, never padded.
func TestScoreBackport_CancelledIsPartialNotPadded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := ScoreBackport(ctx, insts(), alwaysPatch, func(context.Context, BackportInstance, map[string][]string) (bool, string, error) {
		return true, "", nil
	})
	if r.Total != 0 {
		t.Errorf("a pre-cancelled sweep should run nothing, got total=%d", r.Total)
	}
	if r.ResolveRate() != 0 {
		t.Error("an empty report must not report a rate")
	}
}

// No dataset → the renderer says so plainly instead of printing a fake 0%.
func TestRenderBackport_NoDatasetSaysSo(t *testing.T) {
	out := RenderBackport(&BackportReport{})
	if !strings.Contains(strings.ToLower(out), "no tasks run") {
		t.Errorf("empty report should state the dataset is absent, got:\n%s", out)
	}
}
