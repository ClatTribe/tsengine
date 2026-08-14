package platformapi

import (
	"net/http"
)

// localize.go exposes T2 — "where is the fix?" — to a HUMAN.
//
// A scanner tells you a rule fired. It often cannot tell you WHICH FILE to open: a dependency finding
// points at a lockfile, a cloud finding at an ARN, and a repo finding's file:line is frequently
// approximate or absent. The localizer answers that from the repo's own contents, and — like
// search_estate before it — it was built for the agent and reachable by nobody else. A capability we
// measured, published a score for, and never delivered to a person.
//
// SAME ADAPTER AS THE AGENT'S TOOL, deliberately, for the same reason /v1/ask shares estateSearch: two
// implementations would drift and then the agent and the dashboard would disagree about where the bug
// is. Correctness is pinned once, and both callers inherit it.
//
// GROUNDED (§10). Candidates are built from the repository's real file list, so a ranking can only ever
// cite files that exist. The honest negatives are answers, not failures, and are returned as prose the
// UI shows verbatim: no repo connected ("this is not a statement about the finding"), no readable
// source, or no file carrying sink evidence for the class — which usually means the finding is a
// configuration or dependency issue rather than a code one.
func (d Deps) handleLocalize(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errBody("which finding? pass a finding id"))
		return
	}
	answer, err := (vulnLocalizer{d: d, tenantID: tenantID}).Locate(r.Context(), id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"finding_id": id, "answer": answer})
}
