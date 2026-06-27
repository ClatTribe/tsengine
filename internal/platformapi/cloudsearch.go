package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudsearch"
)

// handleCloudSearch is "search your cloud like a database" (Aikido /Cloud parity). A POSTed cloud inventory
// snapshot (the same shape /v1/cloud/drift takes) + a query → the matching resources and their immediate
// relationships. Grounded (§10): every result is a real resource/edge from the supplied inventory. The
// posted-snapshot path works today; persisting the tenant's last inventory so it can be queried any time
// (without re-posting) is the documented follow-on, mirroring the continuous-drift wiring.
func (d Deps) handleCloudSearch(w http.ResponseWriter, r *http.Request, _ string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var req struct {
		Inventory cloudgraph.Inventory `json:"inventory"`
		Query     cloudsearch.Query    `json:"query"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid cloud-search request: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, cloudsearch.Search(req.Inventory, req.Query))
}
