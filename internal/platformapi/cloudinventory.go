package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
)

// handleIngestAWSInventory (POST /v1/cloud/inventory) is the live-collector ingest for the wedge's CLOUD
// surface. An external collector that holds AWS creds (a CI job, the customer's own script, or the gated
// SDK fetcher) POSTs the account's raw IAM + security-group + S3 state; the platform maps it
// (awsinventory.Build — grounded §10: trust edges only from real policies, internet-reach only when a SG
// actually opens the port) into the attack-path Inventory and STORES it as the tenant's cloud snapshot. So
// the AI Cloud Engineer (/v1/cloud/investigate), drift, and search reason over the REAL account state, not
// a hand-posted file — turning "find the attack path across all three" into a connected-account reality.
// Mirrors /v1/osint/ingest: the posted-snapshot path works today with no tsengine-side creds.
func (d Deps) handleIngestAWSInventory(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.CloudSnapshots == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("cloud snapshot store not configured"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		respond(w, nil, err)
		return
	}
	var raw awsinventory.RawAWS
	if err := json.Unmarshal(body, &raw); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid AWS inventory body"))
		return
	}
	inv := awsinventory.Build(raw)
	invJSON, err := json.Marshal(inv)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if err := d.CloudSnapshots.Put(r.Context(), cloudsnap.Snapshot{
		TenantID: tenantID, Inventory: invJSON, CapturedAt: time.Now().UTC(),
	}); err != nil {
		respond(w, nil, err)
		return
	}
	internetEdges := 0
	for _, e := range inv.Reaches {
		if e.From == cloudgraph.InternetID {
			internetEdges++
		}
	}
	if d.Recorder != nil {
		d.Recorder.Record("aws inventory ingested", "cloud-collector",
			map[string]any{"tenant_id": tenantID, "account_id": inv.AccountID, "resources": len(inv.Resources)},
			"live AWS inventory collected → stored for the AI cloud engineer")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"account_id":     inv.AccountID,
		"resources":      len(inv.Resources),
		"trust_edges":    len(inv.Trusts),
		"internet_edges": internetEdges,
		"stored":         true,
	})
}
