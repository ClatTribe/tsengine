package platformapi

import (
	"net/http"
	"strings"
)

// ask.go exposes T6 — "ask your estate" — to a HUMAN.
//
// THE GAP THIS CLOSES. estateSearch was built for the agent and constructed only inside
// EngineerCatalog, so the AI could answer "are we exposed to log4j?" over the tenant's own findings and
// the person paying for it could not. Every other route in this file family serves a human; this
// capability existed and was reachable by nobody. The notes describing search_estate call it "the tool a
// security engineer reaches for most and the one the product never had" — it was half-built: given to
// the agent, withheld from the operator.
//
// ONE ANSWER, NOT TWO. The handler calls the SAME estateSearch the agent's tool calls. That is
// deliberate and it is the whole design: a separate human-facing query implementation would drift, and
// then the agent and the dashboard would disagree about the customer's own estate — the one place a
// product cannot afford two answers. Correctness is already pinned by the T6 tests
// (engineer_correctness_test.go) and they now cover both callers by construction.
//
// GROUNDED (§10). It reads the tenant's stored findings and assets and renders what it found. No model
// is involved, so it cannot embellish, and an empty result means the estate genuinely has no match
// rather than that a model failed to recall one.
func (d Deps) handleAsk(w http.ResponseWriter, r *http.Request, tenantID string) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, http.StatusBadRequest, errBody("ask what? pass ?q= — e.g. 'critical unproven findings' or 'anything mentioning log4j'"))
		return
	}
	// Bounded: a query is a search string, not a payload. Long input is truncated rather than refused so
	// a pasted stack trace still answers instead of erroring.
	if len(q) > 400 {
		q = q[:400]
	}
	answer, err := (estateSearch{d: d, tenantID: tenantID}).Search(r.Context(), q)
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": q, "answer": answer})
}
