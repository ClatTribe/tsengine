// Package attackcoverage answers "which attacker techniques did we actually exercise against this
// estate, and which did nobody check?"
//
// Every tool wrapper already declares the ATT&CK techniques its detections speak to
// (tool.Tool.MITRETechniques, 46 tools, 30 distinct techniques) and every finding carries the
// techniques it maps to. Neither was ever aggregated, so the product could not answer the question
// buyers in this category compare on — and, more importantly, could not say which techniques went
// UNCHECKED, which is the half that keeps a coverage claim honest.
//
// # The denominator is stated, never invented
//
// The obvious version of this view computes "we cover N% of MITRE ATT&CK". We refuse to, and the
// reason is structural rather than modest: we do not ship the ATT&CK Enterprise catalogue, so the
// only denominator available is the set of techniques OUR OWN TOOLS DECLARE. A percentage over that
// is a tautology — "we cover 30 of the 30 we cover" — dressed as a measurement, and it is exactly
// the shape §10 forbids: a number that cannot go down.
//
// So this reports counts and never a percentage, and Report.Denominator says in words what the
// universe is. Adding a real percentage requires ingesting the real catalogue first.
//
// What it CAN say honestly, and what makes it worth having: of the techniques our tooling speaks to,
// which were exercised against THIS estate (a tenant with no cloud account never exercises cloud
// techniques, however many cloud tools we ship), which came back clean, and which were not exercised
// at all — with the reason.
package attackcoverage

import (
	"sort"

	"github.com/ClatTribe/tsengine/internal/coverage"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Status of one technique against one estate.
const (
	// StatusObserved: a tool that speaks to this technique ran, and findings carry it.
	StatusObserved = "observed"
	// StatusExercisedClean: a covering tool really ran and surfaced nothing for it. This is the only
	// status that means "we looked and it was fine".
	StatusExercisedClean = "exercised_clean"
	// StatusNotExercised: nothing that speaks to this technique ran against this estate. NOT clean —
	// the distinction this whole package exists to preserve.
	StatusNotExercised = "not_exercised"
)

// Technique is one ATT&CK technique's standing against an estate.
type Technique struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"` // empty when we have no transcribed name — never invented
	// Tools are OUR tools that declare this technique, whether or not they ran.
	Tools  []string `json:"tools"`
	Status string   `json:"status"`
	// Findings counts findings carrying this technique. Only meaningful when Status is observed.
	Findings int `json:"findings,omitempty"`
	// Why explains a not_exercised status — no asset of a type whose tools cover it, or the covering
	// tool failed. A gap with no reason is barely better than no gap at all.
	Why string `json:"why,omitempty"`
}

// Report is the estate-wide view.
type Report struct {
	Techniques     []Technique `json:"techniques"`
	Observed       int         `json:"observed"`
	ExercisedClean int         `json:"exercised_clean"`
	NotExercised   int         `json:"not_exercised"`
	// Denominator states what universe these counts are over. Rendered verbatim: a coverage view
	// without its denominator is the number people quote and nobody checks.
	Denominator string `json:"denominator"`
}

const denominator = "Counts are over the ATT&CK techniques tsengine's own tools declare, not over " +
	"MITRE ATT&CK Enterprise. We do not ship the full catalogue, so a percentage here would measure " +
	"us against ourselves. Techniques no tsengine tool speaks to are absent from this view entirely."

// Compute builds the report from the tenant's assets, findings and completed engagements.
//
// Grounded (§10): a technique reads exercised ONLY when a tool that declares it is an anchor for an
// asset type this tenant actually has AND that asset was really scanned AND that tool did not fail.
// Everything else is not_exercised with the reason, never clean.
func Compute(assets []platform.Asset, findings []types.Finding, engagements []platform.Engagement) Report {
	cov := coverage.Compute(assets, findings, engagements)

	// Which of our tools actually ran, across the whole estate, and which failed.
	ran, failed := map[string]bool{}, map[string]bool{}
	for _, a := range cov.Assets {
		if !a.Scanned {
			continue
		}
		for _, t := range a.RunsTools {
			ran[t] = true
		}
		for _, t := range a.ToolsFailed {
			failed[t.Tool] = true
		}
	}

	// Technique → the tools of ours that speak to it.
	byTech := map[string][]string{}
	for _, tl := range tool.All() {
		for _, tech := range tl.MITRETechniques() {
			byTech[tech] = append(byTech[tech], tl.Name())
		}
	}

	// Technique → findings that carry it.
	hits := map[string]int{}
	for _, f := range findings {
		for _, tech := range f.MITRETechniques {
			hits[tech]++
		}
	}

	ids := make([]string, 0, len(byTech))
	for id := range byTech {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rep := Report{Denominator: denominator}
	for _, id := range ids {
		tools := byTech[id]
		sort.Strings(tools)
		t := Technique{ID: id, Name: Names[id], Tools: tools}

		var anyRan, anyFailed bool
		for _, name := range tools {
			if ran[name] {
				anyRan = true
			}
			if failed[name] {
				anyFailed = true
			}
		}
		switch {
		case hits[id] > 0:
			t.Status, t.Findings = StatusObserved, hits[id]
			rep.Observed++
		case anyRan:
			t.Status = StatusExercisedClean
			rep.ExercisedClean++
		default:
			t.Status = StatusNotExercised
			rep.NotExercised++
			t.Why = "no asset was scanned by a tool that covers this technique"
			if anyFailed {
				// A tool that FAILED is a different and more actionable gap than one that was never
				// applicable: the coverage was expected and did not happen.
				t.Why = "the tool that covers this technique failed on the last scan"
			}
		}
		rep.Techniques = append(rep.Techniques, t)
	}
	return rep
}
