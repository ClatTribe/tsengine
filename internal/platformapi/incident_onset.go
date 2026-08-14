package platformapi

import (
	"context"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudhistory"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// annotateOnset tells a responder WHEN the state behind an incident changed.
//
// This is what the estate timeline was built for. On its own, a timeline is a thing you could go and
// consult; nobody does, because during an incident nobody goes looking for a second screen. Attached to
// the alert, it changes the alert's meaning: "this bucket is public" is a fact that gets triaged next
// week, and "this bucket became public forty minutes ago" is something someone deals with now. Until
// this, a responder holding the first had no way to tell which one it was.
//
// READ-TIME AND NEVER PERSISTED, the same pattern as annotateSLA and annotateBlastRadius. That matters
// here for the usual reason plus one more: the timeline grows after an incident opens, so an onset
// frozen at open time would go stale, and a later capture that better explains the change would never
// reach the alert.
//
// GROUNDED (§10), with two refusals that carry most of the value:
//
//   - It matches an incident to a resource by LITERAL containment of the resource id in the incident's
//     endpoint (longest match wins — the same attribution rule the data-tier and per-asset compliance
//     views use). A near-miss is left unannotated rather than guessed at, because attaching the wrong
//     change to an incident sends a responder down a false timeline, which is worse than sending them
//     with nothing.
//   - It reports when we FIRST SAW the change, never when it happened. We observe between captures, so
//     those are different facts, and the note says so on every annotation rather than letting a reader
//     silently treat one as the other.
func (d Deps) annotateOnset(ctx context.Context, tenantID string, incs []platform.Incident) {
	if d.CloudHistory == nil || d.Store == nil || len(incs) == 0 {
		return
	}
	timeline, err := d.CloudHistory.Timeline(ctx, tenantID)
	if err != nil || len(timeline) < 2 {
		return // fewer than two captures: nothing to compare, so nothing honest to say
	}

	// Every observed change, newest last, so a resource that changed repeatedly annotates with its most
	// recent transition — the one a responder is looking at.
	latest := map[string]cloudhistory.Change{}
	for i := 1; i < len(timeline); i++ {
		for _, c := range cloudhistory.Diff(timeline[i-1], timeline[i]) {
			latest[c.ResourceID] = c
		}
	}
	if len(latest) == 0 {
		return
	}

	// The endpoint comes from the incident's own finding — the same join annotateBlastRadius uses,
	// rather than re-parsing the composite incident key.
	findings, ferr := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if ferr != nil {
		return
	}
	epByFinding := make(map[string]string, len(findings))
	for _, f := range findings {
		epByFinding[f.ID] = f.Endpoint
	}

	for i := range incs {
		ep := epByFinding[incs[i].FindingID]
		if ep == "" {
			continue
		}
		best, bestLen := cloudhistory.Change{}, 0
		for id, c := range latest {
			// Longest literal match wins: a bucket arn and its name may both appear, and the more
			// specific one is the one that identifies the resource.
			if len(id) > bestLen && strings.Contains(ep, id) {
				best, bestLen = c, len(id)
			}
		}
		if bestLen == 0 {
			continue // no grounded match — leave it unannotated rather than attach a plausible wrong one
		}
		incs[i].Onset = &platform.Onset{
			At: best.At, What: best.What, ResourceID: best.ResourceID,
			Note: "This is when the change was FIRST OBSERVED, in the capture at this time — not " +
				"necessarily when it happened. State is compared between captures, so the change occurred " +
				"somewhere in the interval before it.",
		}
	}
}
