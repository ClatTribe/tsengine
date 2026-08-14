package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/correlate"
)

func chain(sev string, steps ...correlate.Step) correlate.Chain {
	return correlate.Chain{Severity: sev, Steps: steps}
}

func step(findingID, title, via string) correlate.Step {
	return correlate.Step{FindingID: findingID, Title: title, ViaEntity: via}
}

// THE POINT OF THE WHOLE FILE: three paths through one trust relationship is ONE fix, and saying so is
// the difference between a list and a decision.
func TestChokePoints_FindsTheSharedBridge(t *testing.T) {
	role := "arn:aws:iam::1:role/deploy"
	got := ChokePoints([]correlate.Chain{
		chain("critical", step("f1", "Leaked AWS key", role), step("f2", "S3 public", "")),
		chain("high", step("f3", "Breached SaaS login", role), step("f4", "RDS reachable", "")),
		chain("high", step("f5", "Exposed host", role), step("f6", "Secrets store", "")),
	})
	if len(got) == 0 {
		t.Fatal("no choke point found — three paths run through the same role and the reader is left " +
			"with three separate pieces of work")
	}
	top := got[0]
	if top.Ref != role {
		t.Errorf("top choke point is %q, want the shared role %q", top.Ref, role)
	}
	if top.Paths != 3 {
		t.Errorf("shared role appears in %d paths, want 3", top.Paths)
	}
	if top.WorstSeverity != "critical" {
		t.Errorf("worst severity %q, want critical — a choke point inherits the worst path it sits on", top.WorstSeverity)
	}
}

// Something in ONE path is not leverage, it is the path. Reporting it would turn every finding into a
// "choke point" and make the ranking meaningless.
func TestChokePoints_SinglePathIsNotAChokePoint(t *testing.T) {
	got := ChokePoints([]correlate.Chain{
		chain("high", step("f1", "Only finding", "entity-a")),
	})
	if len(got) != 0 {
		t.Errorf("reported %d choke point(s) from a single path — leverage requires overlap: %+v", len(got), got)
	}
}

// No shared element is a REAL answer: the paths are genuinely separate work. Promoting the
// least-unshared thing to look decisive would be worse than saying nothing.
func TestChokePoints_NoOverlapReportsNothing(t *testing.T) {
	got := ChokePoints([]correlate.Chain{
		chain("critical", step("f1", "A", "key-1")),
		chain("high", step("f2", "B", "key-2")),
	})
	if len(got) != 0 {
		t.Errorf("invented a choke point where the paths share nothing: %+v", got)
	}
}

// A bridge repeated inside ONE path is still one path. Counting repeats would rank a self-referential
// path above three genuinely distinct ones.
func TestChokePoints_RepeatsWithinOnePathCountOnce(t *testing.T) {
	got := ChokePoints([]correlate.Chain{
		chain("high", step("f1", "A", "role-x"), step("f2", "B", "role-x"), step("f3", "C", "role-x")),
	})
	if len(got) != 0 {
		t.Errorf("a single path counted as multiple: %+v", got)
	}
}

// Most leverage first, then worst severity — a choke point on three low paths must not outrank one on
// three critical ones.
func TestChokePoints_RankedByLeverageThenSeverity(t *testing.T) {
	got := ChokePoints([]correlate.Chain{
		chain("low", step("f1", "A", "low-shared")),
		chain("low", step("f2", "B", "low-shared")),
		chain("critical", step("f3", "C", "crit-shared")),
		chain("critical", step("f4", "D", "crit-shared")),
	})
	if len(got) < 2 {
		t.Fatalf("expected both choke points, got %+v", got)
	}
	if got[0].WorstSeverity != "critical" {
		t.Errorf("at equal path counts the critical choke point must lead, got %q first", got[0].WorstSeverity)
	}
}

// Entities and findings are different work — revoking a key is not the same as fixing a bug — so they
// must not be merged into one row even if the strings collide.
func TestChokePoints_EntityAndFindingAreNotMerged(t *testing.T) {
	got := ChokePoints([]correlate.Chain{
		chain("high", step("same", "A", "same")),
		chain("high", step("same", "B", "same")),
	})
	kinds := map[string]bool{}
	for _, c := range got {
		kinds[c.Kind] = true
	}
	if !kinds["entity"] || !kinds["finding"] {
		t.Errorf("expected both an entity and a finding choke point, got %+v", got)
	}
}

// The order must be stable — a ranking that shuffles between identical runs teaches a reader to
// distrust it.
func TestChokePoints_StableOrder(t *testing.T) {
	in := []correlate.Chain{
		chain("high", step("f1", "A", "e1")), chain("high", step("f2", "B", "e1")),
		chain("high", step("f3", "C", "e2")), chain("high", step("f4", "D", "e2")),
	}
	first := ChokePoints(in)
	for i := 0; i < 20; i++ {
		got := ChokePoints(in)
		for j := range got {
			if got[j].Ref != first[j].Ref {
				t.Fatalf("order changed between runs at %d: %q vs %q", j, got[j].Ref, first[j].Ref)
			}
		}
	}
}
