package platformapi

import (
	"encoding/json"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/safechain"
	"github.com/ClatTribe/tsengine/internal/supplychain"
)

// handleSafeChain is the install-time supply-chain gate (Aikido "Safe Chain" parity). A CI step — or a
// future npm/yarn/npx CLI shim — POSTs the packages an install WOULD add; the response says whether each is
// safe and whether the install may proceed, BEFORE a hostile package ever runs. The malicious-package
// corpus is GLOBAL world-state (the same one the repository scanner uses), so the verdict is tenant-agnostic
// and grounded — a block is only ever a real known-malicious match (§10); unknown packages are allowed.
func (d Deps) handleSafeChain(w http.ResponseWriter, r *http.Request, _ string) {
	var body struct {
		Packages []supplychain.Package `json:"packages"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if len(body.Packages) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("packages: at least one {ecosystem,name,version} required"))
		return
	}
	writeJSON(w, http.StatusOK, safechain.CheckAll(body.Packages, supplychain.DefaultCorpus()))
}
