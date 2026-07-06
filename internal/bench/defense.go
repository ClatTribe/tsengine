package bench

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/retest"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// defense.go is the DEFENSIVE benchmark — the AI Security Engineer's XBOW twin. XBOW scores the attacker
// ("did you capture the flag", execution-verified + binary); this scores the defender ("did the estate get
// verifiably safer"). The hero metric is REMEDIATION CAPTURE: the engineer proposes fixes, and a re-scan
// (here the scenario's post-fix oracle) proves the finding is gone — reusing retest.Verify so the bench and
// the product share ONE definition of "fixed" (they can never drift). Around it sit three secondary
// dimensions: attack-path recall (did it find the cross-surface chain), triage precision (did it leave the
// decoys alone), and grounding (did it invent nothing). Deterministic + LLM-free to SCORE — the SUT that
// PRODUCES the actions is either the deterministic substrate (remediate.Propose) or the LLM engineer, and
// the delta between them is the agent's measured lift (the substrate-vs-agent ablation, §14.1 discipline).

// DefenseScenario is one seeded code+cloud estate with a known answer key — the defensive analog of an
// XBOW challenge. The SUT reads Before + Assets and must remediate it; After is the ground-truth re-scan
// AFTER the correct fixes (in a live run, captured from a real re-scan; in a fixture, authored).
type DefenseScenario struct {
	ID          string           `json:"id"`
	Name        string           `json:"name,omitempty"`
	Assets      []platform.Asset `json:"assets,omitempty"`
	Before      []types.Finding  `json:"before"`                 // the vulnerable estate (initial scan)
	After       []types.Finding  `json:"after"`                  // the estate AFTER the correct remediations (the oracle)
	Decoys      []string         `json:"decoys,omitempty"`       // finding keys (rule_id|endpoint) that must NOT be actioned
	AttackPaths []PathSig        `json:"attack_paths,omitempty"` // expected cross-surface chains (grounded answer key)
}

// PathSig is a signature of an expected cross-surface attack path — matched loosely against a produced
// crossdetect chain so a scenario doesn't have to pin exact titles: an entry surface, a cloud target
// substring, and (optionally) the shared entity that bridges them.
type PathSig struct {
	EntrySurface string `json:"entry_surface"`        // e.g. "repository"
	CloudTarget  string `json:"cloud_target"`         // substring of the reached cloud crown-jewel step
	ViaEntity    string `json:"via_entity,omitempty"` // optional shared-entity kind, e.g. "aws_key"
}

// DefenseScore is the grade for one scenario run. RemediationCapture is the hero number.
type DefenseScore struct {
	ScenarioID string `json:"scenario_id"`

	// Remediation capture (HERO) — execution-verified via retest.Verify against the post-fix oracle.
	Closeable        int     `json:"closeable"`         // vulns a correct pipeline closes (keys in Before \ After)
	Captured         int     `json:"captured"`          // of those, the SUT proposed a fix that verified FIXED
	RemediationRate  float64 `json:"remediation_rate"`  // Captured / Closeable  (1.0 == closed everything closeable)
	IneffectiveFixes int     `json:"ineffective_fixes"` // actions whose finding is STILL present post-fix (wrong fix)

	// Attack-path recall — did the engineer surface the cross-surface chains.
	ExpectedPaths int `json:"expected_paths"`
	FoundPaths    int `json:"found_paths"`

	// Triage precision — a decoy that got actioned is a false action (noise the engineer should ignore).
	DecoyActions int `json:"decoy_actions"`

	// Grounding (§10) — any recorded finding whose key exists in NEITHER Before nor After is invented.
	Invented []string `json:"invented,omitempty"`
}

// PathRecall is FoundPaths/ExpectedPaths (1.0 when no paths are expected).
func (s DefenseScore) PathRecall() float64 {
	if s.ExpectedPaths == 0 {
		return 1.0
	}
	return float64(s.FoundPaths) / float64(s.ExpectedPaths)
}

// Pass is the XBOW-style clean bar: closed everything closeable, found every expected path, actioned no
// decoy, invented nothing. A partial run is reported by the numbers, not hidden by a soft pass.
func (s DefenseScore) Pass() bool {
	return s.RemediationRate >= 1.0 && s.PathRecall() >= 1.0 && s.DecoyActions == 0 && len(s.Invented) == 0
}

// ScoreDefense grades a SUT's output against a scenario. `proposed` are the remediation actions the SUT
// produced (from remediate.Propose in substrate mode, or the LLM engineer in agent mode) — each should
// carry FindingIDs (the findings it resolves). `recorded` are any findings the SUT itself asserted (for
// the grounding check; nil in substrate mode). Pure + deterministic: it stamps each action's FindingKeys
// from Before, marks it applied, and runs the SAME retest.Verify the product uses against the After oracle.
func ScoreDefense(sc DefenseScenario, proposed []platform.Action, recorded []types.Finding) DefenseScore {
	s := DefenseScore{ScenarioID: sc.ID}

	beforeKeys := keySet(sc.Before)
	afterKeys := keySet(sc.After)
	decoy := map[string]bool{}
	for _, d := range sc.Decoys {
		decoy[d] = true
	}

	// Closeable = the vulns a correct remediation removes (present Before, absent After).
	closeable := map[string]bool{}
	for k := range beforeKeys {
		if !afterKeys[k] {
			closeable[k] = true
		}
	}
	s.Closeable = len(closeable)

	// Stamp + apply each proposed action so retest.Verify can grade it against the After oracle. Also
	// tally decoy actions (a proposal that targets a key the scenario marked benign noise).
	acts := make([]platform.Action, 0, len(proposed))
	for _, a := range proposed {
		ids := a.FindingIDs
		if len(ids) == 0 && a.FindingID != "" {
			ids = []string{a.FindingID}
		}
		a.Status = platform.ActApplied
		a.FindingKeys = retest.KeysForIDs(ids, sc.Before)
		for _, k := range a.FindingKeys {
			if decoy[k] {
				s.DecoyActions++
			}
		}
		acts = append(acts, a)
	}

	// Hero metric: re-verify every applied action against the post-fix oracle (After). A key confirmed
	// gone AND in the closeable set counts as a capture; a key still present is an ineffective fix.
	captured := map[string]bool{}
	for _, verified := range retest.Verify(acts, sc.After, time.Unix(0, 0).UTC()) {
		if verified.Verification == nil {
			continue
		}
		for _, k := range verified.Verification.Fixed {
			if closeable[k] {
				captured[k] = true
			}
		}
		s.IneffectiveFixes += len(verified.Verification.StillPresent)
	}
	s.Captured = len(captured)
	if s.Closeable > 0 {
		s.RemediationRate = float64(s.Captured) / float64(s.Closeable)
	} else {
		s.RemediationRate = 1.0 // nothing to close → vacuously complete
	}

	// Attack-path recall — run the SAME crossdetect correlation the product uses over the vulnerable
	// estate and match each expected signature.
	s.ExpectedPaths = len(sc.AttackPaths)
	if s.ExpectedPaths > 0 {
		chains := crossdetect.Correlate(sc.Assets, sc.Before)
		for _, want := range sc.AttackPaths {
			if matchesPath(want, chains) {
				s.FoundPaths++
			}
		}
	}

	// Grounding (§10): a recorded finding whose key is in neither Before nor After was invented.
	for _, f := range recorded {
		k := detect.Key(f)
		if !beforeKeys[k] && !afterKeys[k] {
			s.Invented = append(s.Invented, k)
		}
	}
	sort.Strings(s.Invented)
	return s
}

func keySet(fs []types.Finding) map[string]bool {
	m := make(map[string]bool, len(fs))
	for _, f := range fs {
		m[detect.Key(f)] = true
	}
	return m
}

// matchesPath reports whether any produced chain satisfies the expected signature: a step on the entry
// surface, a cloud_account step whose title/target contains CloudTarget, and (if set) the ViaEntity
// somewhere on the chain.
func matchesPath(want PathSig, chains []correlate.Chain) bool {
	for _, ch := range chains {
		var hasEntry, hasCloud, hasVia bool
		hasVia = want.ViaEntity == ""
		for _, st := range ch.Steps {
			if want.EntrySurface != "" && st.AssetType == want.EntrySurface {
				hasEntry = true
			}
			if st.AssetType == "cloud_account" &&
				(strings.Contains(strings.ToLower(st.Title), strings.ToLower(want.CloudTarget)) ||
					strings.Contains(strings.ToLower(st.AssetTarget), strings.ToLower(want.CloudTarget))) {
				hasCloud = true
			}
			if want.ViaEntity != "" && strings.Contains(strings.ToLower(st.ViaEntity), strings.ToLower(want.ViaEntity)) {
				hasVia = true
			}
		}
		if hasEntry && hasCloud && hasVia {
			return true
		}
	}
	return false
}

// RenderDefenseScore is a one-line human summary of a scenario grade.
func RenderDefenseScore(s DefenseScore) string {
	return fmt.Sprintf("%s: remediation %d/%d (%.0f%%) · paths %d/%d · decoy-actions %d · invented %d%s",
		s.ScenarioID, s.Captured, s.Closeable, s.RemediationRate*100, s.FoundPaths, s.ExpectedPaths,
		s.DecoyActions, len(s.Invented), passSuffix(s.Pass()))
}

func passSuffix(pass bool) string {
	if pass {
		return " [PASS]"
	}
	return ""
}
