package detectionskill

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/correlate"
)

func chain(ids ...string) correlate.Chain {
	ch := correlate.Chain{Severity: "high"}
	for _, id := range ids {
		ch.Steps = append(ch.Steps, correlate.Step{FindingID: id, AssetTarget: "asset-" + id})
	}
	return ch
}

func res(v Verdict, skill string) Result {
	return Result{Verdict: v, SkillName: skill, SkillDigest: "abcdef0123456789", Rationale: "because"}
}

// THE composition value: two DIFFERENT skills, on different surfaces, independently flagging two
// hops of the same path. No single-detection skill can observe this.
func TestCompose_CrossSurfaceCorroboration(t *testing.T) {
	a := ComposeChain(chain("f-1", "f-2", "f-3"), map[string]Result{
		"f-1": res(VerdictSuspicious, "code-leaked-key"),
		"f-2": res(VerdictMalicious, "cloud-iam-privesc"),
	})

	if a.Verdict != VerdictMalicious {
		t.Fatalf("chain verdict should be the strongest step reached, got %q", a.Verdict)
	}
	if !a.Corroborated() || a.Corroboration != 2 {
		t.Fatalf("two distinct skills flagged this path — corroboration = %d", a.Corroboration)
	}
	if a.Assessed != 2 || a.Total != 3 {
		t.Fatalf("coverage wrong: %d/%d", a.Assessed, a.Total)
	}
}

// One skill matching several steps is ONE opinion applied repeatedly, not independent agreement.
func TestCompose_SameSkillTwiceIsNotCorroboration(t *testing.T) {
	a := ComposeChain(chain("f-1", "f-2"), map[string]Result{
		"f-1": res(VerdictSuspicious, "same-skill"),
		"f-2": res(VerdictSuspicious, "same-skill"),
	})
	if a.Corroboration != 1 || a.Corroborated() {
		t.Fatalf("one skill twice must not read as independent agreement; corroboration=%d", a.Corroboration)
	}
}

// THE GROUNDING RULE: composing aggregates but never escalates. A chain whose assessed steps are all
// benign must compose to benign — otherwise a chain would manufacture severity no evidence supports.
func TestCompose_NeverEscalatesBeyondItsSteps(t *testing.T) {
	a := ComposeChain(chain("f-1", "f-2"), map[string]Result{
		"f-1": res(VerdictBenign, "s1"),
		"f-2": res(VerdictBenign, "s2"),
	})
	if a.Verdict != VerdictBenign {
		t.Fatalf("all-benign steps must compose to benign, got %q", a.Verdict)
	}
	if a.Corroboration != 0 {
		t.Errorf("benign verdicts are not corroboration of a threat; got %d", a.Corroboration)
	}
}

// "We could not tell" must not be composed away by a benign hop elsewhere on the path.
func TestCompose_InconclusiveOutranksBenign(t *testing.T) {
	a := ComposeChain(chain("f-1", "f-2"), map[string]Result{
		"f-1": res(VerdictBenign, "s1"),
		"f-2": res(VerdictInconclusive, "s2"),
	})
	if a.Verdict != VerdictInconclusive {
		t.Fatalf("inconclusive must survive a benign sibling, got %q", a.Verdict)
	}
}

// An unassessed chain has NO verdict — not a benign one. Treating "nobody looked" as "it's fine" is
// the most dangerous possible default.
func TestCompose_UnassessedChainHasNoVerdict(t *testing.T) {
	a := ComposeChain(chain("f-1", "f-2"), map[string]Result{})
	if a.Verdict != "" {
		t.Fatalf("an unassessed chain must have no verdict, got %q", a.Verdict)
	}
	if a.Coverage() != 0 {
		t.Errorf("coverage should be 0, got %v", a.Coverage())
	}
	if !strings.Contains(a.Narrative(), "unassessed") {
		t.Errorf("the narrative must say it was unassessed: %q", a.Narrative())
	}
}

// Partial coverage must be stated, never implied away.
func TestCompose_NarrativeStatesCoverageHonestly(t *testing.T) {
	a := ComposeChain(chain("f-1", "f-2", "f-3", "f-4"), map[string]Result{
		"f-1": res(VerdictSuspicious, "s1"),
	})
	n := a.Narrative()
	if !strings.Contains(n, "1 of 4 steps assessed") {
		t.Errorf("narrative must state coverage: %q", n)
	}
	if !strings.Contains(n, "3 step(s) had no covering skill") {
		t.Errorf("narrative must name the unassessed remainder: %q", n)
	}
	if a.Coverage() != 0.25 {
		t.Errorf("coverage = %v, want 0.25", a.Coverage())
	}
}

func TestComposeChains_StrongestFirst(t *testing.T) {
	weak := chain("f-9")
	strong := chain("f-1", "f-2")
	byFinding := map[string]Result{
		"f-9": res(VerdictBenign, "s0"),
		"f-1": res(VerdictMalicious, "s1"),
		"f-2": res(VerdictSuspicious, "s2"),
	}
	got := ComposeChains([]correlate.Chain{weak, strong}, byFinding)
	if len(got) != 2 {
		t.Fatalf("got %d assessments", len(got))
	}
	if got[0].Verdict != VerdictMalicious {
		t.Fatalf("the strongest path must lead, got %q first", got[0].Verdict)
	}
	if !got[0].Corroborated() {
		t.Error("the leading path should be the corroborated one")
	}
}

func TestCompose_StepsAlignWithChain(t *testing.T) {
	ch := chain("f-1", "f-2", "f-3")
	a := ComposeChain(ch, map[string]Result{"f-2": res(VerdictSuspicious, "s")})
	if len(a.Steps) != len(ch.Steps) {
		t.Fatalf("steps must align 1:1 with the chain: %d vs %d", len(a.Steps), len(ch.Steps))
	}
	if a.Steps[0].Assessed() || !a.Steps[1].Assessed() || a.Steps[2].Assessed() {
		t.Fatalf("assessment flags misaligned: %+v", a.Steps)
	}
	if a.Steps[1].Skill != "s@abcdef012345" {
		t.Errorf("provenance not carried onto the step: %q", a.Steps[1].Skill)
	}
}

func TestCompose_EmptyChain(t *testing.T) {
	a := ComposeChain(correlate.Chain{}, map[string]Result{})
	if a.Total != 0 || a.Coverage() != 0 {
		t.Fatalf("empty chain mishandled: %+v", a)
	}
	if !strings.Contains(a.Narrative(), "nothing to assess") {
		t.Errorf("narrative: %q", a.Narrative())
	}
}
