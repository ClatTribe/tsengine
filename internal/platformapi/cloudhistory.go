package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/internal/cloudhistory"
)

// handleCloudHistory answers "when did this change?" over the estate's recorded timeline.
//
// WHY IT IS ITS OWN ENDPOINT. Everything else the product serves is about the present: what is exposed
// now, what is unproven now. This is the question asked during an INCIDENT — when did this bucket become
// public, when did this identity first get a path to admin — and it is the one a latest-wins snapshot
// store cannot answer at all.
//
// ?resource=<id> narrows to one resource's transitions; without it the caller gets the whole timeline's
// changes, newest capture last.
//
// HONEST ABOUT ITS LIMITS, because a history that overstates itself is worse than none:
//
//   - It reports transitions BETWEEN CAPTURES. If a bucket was public for an hour between two captures,
//     this cannot see it and does not claim to — so the response states the capture count and window
//     rather than implying continuous observation.
//   - An empty result is not "nothing changed" unless there IS a timeline. With no captures the answer is
//     "we have not been watching long enough", which is a different sentence and the response says which.
//   - It tracks security-relevant ATTRIBUTES (public, privileged, sensitivity), not the whole graph. It is
//     deliberately not a full rewind, and the note says so rather than letting a reader assume otherwise.
func (d Deps) handleCloudHistory(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.CloudHistory == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"changes": []cloudhistory.Change{}, "captures": 0,
			"note": "No estate history is being kept in this deployment, so change over time cannot be " +
				"answered. This is not a statement that nothing changed.",
		})
		return
	}
	timeline, err := d.CloudHistory.Timeline(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}

	resource := r.URL.Query().Get("resource")
	changes := []cloudhistory.Change{}
	if resource != "" {
		changes = append(changes, cloudhistory.WhenChanged(timeline, resource)...)
	} else {
		for i := 1; i < len(timeline); i++ {
			changes = append(changes, cloudhistory.Diff(timeline[i-1], timeline[i])...)
		}
	}

	resp := map[string]any{"changes": changes, "captures": len(timeline)}
	switch {
	case len(timeline) == 0:
		resp["note"] = "No captures yet — post a cloud inventory and the timeline starts. An empty answer " +
			"here means we have not been watching, not that nothing changed."
	case len(timeline) == 1:
		resp["note"] = "Only one capture so far, so there is nothing to compare it against yet. Change " +
			"becomes visible from the second capture on."
	default:
		resp["first_capture"] = timeline[0].CapturedAt
		resp["last_capture"] = timeline[len(timeline)-1].CapturedAt
		resp["note"] = "Transitions are observed BETWEEN captures — a change that happened and reverted " +
			"inside one interval is invisible here. Tracks security-relevant attributes (internet-facing, " +
			"privileged, data sensitivity), not the full graph."
	}
	writeJSON(w, http.StatusOK, resp)
}
