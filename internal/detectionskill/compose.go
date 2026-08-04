package detectionskill

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/correlate"
)

// compose.go is ADR 0017's Compose move — the one that is structurally unavailable to anyone else
// consuming this format.
//
// A Detection Skill is per-detection and single-surface: it reasons about one alert, on one system.
// correlate.Chain already links findings ACROSS surfaces (code → cloud → SaaS) through a real shared
// entity. Running skills over the steps of a chain and composing their verdicts produces something no
// individual skill can: CROSS-SURFACE CORROBORATION. Two skills, written by different authors,
// looking at different systems, independently reaching a non-benign verdict on two hops of the same
// attack path is far stronger evidence than either verdict alone — and no single-detection skill can
// ever observe it.
//
// THE COMPOSITION RULE, which keeps this grounded: composing may AGGREGATE but never ESCALATE beyond
// what the steps support. The chain verdict is the strongest verdict any assessed step reached — it
// is never invented, and a chain whose assessed steps are all benign composes to benign. Otherwise a
// chain would be a way to manufacture severity that no evidence supports, which is exactly the
// failure mode the rest of this package exists to prevent.
//
// Coverage is reported honestly. A chain where one step of five was assessed must never read as a
// fully-assessed attack path.

// StepVerdict is one chain step with the skill verdict for it, if any.
type StepVerdict struct {
	Step    correlate.Step
	Verdict Verdict // empty when no skill covered this step
	Skill   string  // "name@digest" — provenance
	Reason  string
}

// Assessed reports whether a skill actually reached a verdict for this step.
func (s StepVerdict) Assessed() bool { return s.Verdict != "" }

// ChainAssessment is a cross-surface attack path with its steps' skill verdicts composed.
type ChainAssessment struct {
	Chain correlate.Chain
	Steps []StepVerdict // aligned 1:1 with Chain.Steps

	// Verdict is the composed conclusion: the strongest verdict any assessed step reached. Empty
	// when no step was assessed (honest — an unassessed chain has no verdict, not a benign one).
	Verdict Verdict
	// Corroboration counts DISTINCT skills that independently reached a non-benign verdict on this
	// chain. This is the number that matters: >= 2 means separate authored reasoning, on separate
	// surfaces, agreed something is wrong along one path.
	Corroboration int
	// Assessed / Total make coverage explicit rather than implied.
	Assessed int
	Total    int
}

// Coverage is the fraction of chain steps a skill assessed (0 when the chain is empty).
func (a ChainAssessment) Coverage() float64 {
	if a.Total == 0 {
		return 0
	}
	return float64(a.Assessed) / float64(a.Total)
}

// Corroborated reports the strong signal: two or more DISTINCT skills independently flagged steps of
// this same path.
func (a ChainAssessment) Corroborated() bool { return a.Corroboration >= 2 }

// verdictRank orders verdicts by strength for composition. Inconclusive outranks benign because
// "we could not tell" must never be composed away by a benign hop elsewhere on the path.
func verdictRank(v Verdict) int {
	switch v {
	case VerdictMalicious:
		return 4
	case VerdictSuspicious:
		return 3
	case VerdictInconclusive:
		return 2
	case VerdictBenign:
		return 1
	}
	return 0
}

// ComposeChain composes per-finding verdicts along one chain.
//
// `byFinding` maps a finding id to the verdict a skill reached for it (typically built by running
// Triage over the chain's findings). A step with no entry is simply unassessed.
func ComposeChain(ch correlate.Chain, byFinding map[string]Result) ChainAssessment {
	a := ChainAssessment{Chain: ch, Total: len(ch.Steps)}
	distinctSkills := map[string]bool{}

	for _, st := range ch.Steps {
		sv := StepVerdict{Step: st}
		if r, ok := byFinding[st.FindingID]; ok && r.Verdict != "" {
			sv.Verdict, sv.Reason = r.Verdict, r.Rationale
			sv.Skill = r.SkillName + "@" + shortDigest(r.SkillDigest)
			a.Assessed++

			// AGGREGATE, never escalate: take the strongest verdict actually reached.
			if verdictRank(r.Verdict) > verdictRank(a.Verdict) {
				a.Verdict = r.Verdict
			}
			// Corroboration counts DISTINCT skills, so one skill matching several steps of the same
			// chain does not look like independent agreement — it is one opinion applied repeatedly.
			if r.Verdict.Actionable() && r.SkillName != "" {
				distinctSkills[r.SkillName] = true
			}
		}
		a.Steps = append(a.Steps, sv)
	}
	a.Corroboration = len(distinctSkills)
	return a
}

// ComposeChains composes every chain and returns them strongest-first, so the path most supported by
// independent reasoning leads.
func ComposeChains(chains []correlate.Chain, byFinding map[string]Result) []ChainAssessment {
	out := make([]ChainAssessment, 0, len(chains))
	for _, ch := range chains {
		out = append(out, ComposeChain(ch, byFinding))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if r1, r2 := verdictRank(out[i].Verdict), verdictRank(out[j].Verdict); r1 != r2 {
			return r1 > r2
		}
		// Then by independent corroboration, then by how much of the path was actually assessed.
		if out[i].Corroboration != out[j].Corroboration {
			return out[i].Corroboration > out[j].Corroboration
		}
		return out[i].Assessed > out[j].Assessed
	})
	return out
}

// Narrative renders the composed assessment for a human. It states coverage explicitly, so a
// partially-assessed path can never read as a fully-assessed one.
func (a ChainAssessment) Narrative() string {
	if a.Total == 0 {
		return "empty chain — nothing to assess"
	}
	var b strings.Builder
	if a.Verdict == "" {
		fmt.Fprintf(&b, "No skill covered any of the %d step(s) on this path — unassessed.", a.Total)
		return b.String()
	}
	fmt.Fprintf(&b, "%s across a %d-step path (%d of %d steps assessed",
		a.Verdict, a.Total, a.Assessed, a.Total)
	if a.Corroborated() {
		fmt.Fprintf(&b, "; %d independent skills agree", a.Corroboration)
	}
	b.WriteString(").")

	for _, sv := range a.Steps {
		if !sv.Assessed() {
			continue
		}
		fmt.Fprintf(&b, "\n  · %s (%s): %s", sv.Step.AssetTarget, sv.Verdict, sv.Skill)
		if sv.Reason != "" {
			fmt.Fprintf(&b, " — %s", sv.Reason)
		}
	}
	if a.Assessed < a.Total {
		fmt.Fprintf(&b, "\n  · %d step(s) had no covering skill and were not assessed.", a.Total-a.Assessed)
	}
	return b.String()
}
