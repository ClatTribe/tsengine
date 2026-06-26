package grc

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// custom.go is the bring-your-own-framework engine (Sprinto/Vanta parity for the long regional/sector
// tail — CSA STAR, TISAX, C5, FFIEC, …). A tenant defines a CustomFramework whose controls map to signals
// tsengine ALREADY produces (a built-in framework:control, a CWE, or a rule id); the posture is then
// DERIVED from live findings, never asserted (§10) — so a custom framework is as grounded + as honest
// (no false-compliant) as the built-in 22, with zero new detection code.

// DeriveCustomPosture computes a custom framework's control states + coverage from the tenant's findings.
// A control is a GAP when a finding satisfies one of its MapsTo refs (with that finding as evidence); a
// control with no matching finding is left UNASSESSED (never auto-"met" — absence of a finding is not
// proof of compliance). Only controls with a non-empty MapsTo are automatable; the rest need attestation.
func DeriveCustomPosture(cf platform.CustomFramework, findings []types.Finding) ([]platform.ControlState, Coverage) {
	states := make([]platform.ControlState, 0, len(cf.Controls))
	autoEvaluable, gaps := 0, 0
	for _, ctrl := range cf.Controls {
		if len(ctrl.MapsTo) > 0 {
			autoEvaluable++
		}
		seen := map[string]bool{}
		var evidence []string
		for _, f := range findings {
			if matchesAny(f, ctrl.MapsTo) && !seen[f.ID] {
				seen[f.ID] = true
				evidence = append(evidence, f.ID)
			}
		}
		if len(evidence) > 0 {
			states = append(states, platform.ControlState{
				Framework: cf.ID, ControlID: ctrl.ID, State: platform.ControlGap, EvidenceRefs: evidence,
			})
			gaps++
		}
	}
	return states, computeCoverage(cf.ID, autoEvaluable, 0, gaps)
}

func matchesAny(f types.Finding, refs []string) bool {
	for _, ref := range refs {
		if findingMatchesRef(f, ref) {
			return true
		}
	}
	return false
}

// findingMatchesRef reports whether a finding satisfies one MapsTo reference:
//   - "cwe:CWE-89"     → the finding carries that CWE
//   - "rule:sqli"      → the finding's rule id contains the substring (case-insensitive)
//   - "soc2:CC6.1"     → the finding's compliance annotation cites that built-in framework control
func findingMatchesRef(f types.Finding, ref string) bool {
	kind, val, ok := strings.Cut(ref, ":")
	if !ok || val == "" {
		return false
	}
	switch strings.ToLower(kind) {
	case "cwe":
		for _, c := range f.CWE {
			if strings.EqualFold(c, val) {
				return true
			}
		}
	case "rule":
		return strings.Contains(strings.ToLower(f.RuleID), strings.ToLower(val))
	default: // a built-in framework key (soc2, pci, cmmc, …)
		if f.Compliance == nil {
			return false
		}
		for _, c := range frameworkControls(f.Compliance)[strings.ToLower(kind)] {
			if c == val {
				return true
			}
		}
	}
	return false
}
