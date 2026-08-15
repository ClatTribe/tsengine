package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/hitl"
)

// approvals_bulk.go lets one person clear a queue without clicking a hundred times.
//
// The ICP is a security team of one to six. The approval desk is where the product's whole
// human-in-the-loop promise lives, and it decided ONE action per request — which is fine for a
// workspace with three proposals and a tax on the person we built it for. A gate that is too slow to
// use gets bypassed, and a bypassed gate is worse than none, because everyone still believes it is
// there.
//
// # This is a UI affordance over N gated decisions, NOT a new write path
//
// Every id goes through the SAME hitl.Desk.Decide as a single approval. That is the load-bearing
// design choice: the kill-switch still wins over the verdict, an irreversible (T3) action still
// refuses without a named human signature, and every decision is still signed into the ledger
// individually. Nothing here can approve something the single path would have refused — a caller
// cannot use bulk to get a weaker gate, only a faster keyboard.
//
// # Partial failure is reported, not smoothed over
//
// Approving fifty actions where six fail delivery must not read as "50 approved". The response
// reports each failure with its id and reason, because a person who believes fifty tickets were
// filed and finds forty-four is worse off than one who was told six failed.
// maxBulkDecisions bounds one request. High enough to clear a realistic morning queue in one action,
// low enough that a single request cannot hold a worker for minutes — each decision may perform a
// live delivery (a Jira call, a cloud write), so this is real outbound work, not a loop over rows.
const maxBulkDecisions = 200

type bulkDecisionResult struct {
	ID     string `json:"id"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

type bulkDecisionResponse struct {
	Requested int                  `json:"requested"`
	Succeeded int                  `json:"succeeded"`
	Failed    int                  `json:"failed"`
	Results   []bulkDecisionResult `json:"results"`
	Detail    string               `json:"detail"`
}

// handleBulkApprovalDecide applies one verdict to many actions.
func (d Deps) handleBulkApprovalDecide(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.Desk == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("approvals not configured"))
		return
	}
	var body struct {
		IDs            []string `json:"ids"`
		Approver       string   `json:"approver"`
		Approve        bool     `json:"approve"`
		RequestChanges bool     `json:"request_changes,omitempty"`
		Feedback       string   `json:"feedback,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad body: "+err.Error()))
		return
	}
	// The approver is required for the same reason it is on the single path: a decision nobody's name
	// is on cannot be audited, and bulk is exactly where an unattributed approval would hide.
	if strings.TrimSpace(body.Approver) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("name the person making this decision"))
		return
	}
	ids := dedupeIDs(body.IDs)
	if len(ids) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("no actions selected"))
		return
	}
	if len(ids) > maxBulkDecisions {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "that is more than " + itoa(maxBulkDecisions) + " actions in one request — each one " +
				"may file a ticket or write to your cloud, so they are applied in batches",
			"reason": "too_many",
		})
		return
	}

	res := bulkDecisionResponse{Requested: len(ids), Results: make([]bulkDecisionResult, 0, len(ids))}
	for _, id := range ids {
		// The SAME gate as a single approval. Not a fast path, not a batch write — N individually
		// gated, individually signed decisions.
		act, err := d.Desk.Decide(r.Context(), tenantID, id, hitl.Verdict{
			Approver: body.Approver, Approve: body.Approve,
			RequestChanges: body.RequestChanges, Feedback: body.Feedback,
		})
		if err != nil {
			res.Failed++
			res.Results = append(res.Results, bulkDecisionResult{ID: id, Error: err.Error()})
			continue
		}
		res.Succeeded++
		res.Results = append(res.Results, bulkDecisionResult{ID: id, Status: string(act.Status)})
	}
	res.Detail = bulkDetail(res.Succeeded, res.Failed, body.Approve)
	writeJSON(w, http.StatusOK, res)
}

// bulkDetail states the outcome without rounding the failures away.
func bulkDetail(ok, failed int, approve bool) string {
	verb := "rejected"
	if approve {
		verb = "approved"
	}
	switch {
	case failed == 0:
		return plural(ok, "action was", "actions were") + " " + verb + "."
	case ok == 0:
		return "None went through — see the reason on each."
	default:
		return plural(ok, "action was", "actions were") + " " + verb + ", but " +
			plural(failed, "did not go through", "did not go through") + ". Check the reasons below."
	}
}

// dedupeIDs drops blanks and repeats. A double-submitted id would otherwise be decided twice, and the
// second decision would fail confusingly on an action no longer pending.
func dedupeIDs(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, id := range in {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
