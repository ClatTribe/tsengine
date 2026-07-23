package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/clouddrift"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/connector/azinventory"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleIngestAWSInventory (POST /v1/cloud/inventory) is the live-collector ingest for the wedge's CLOUD
// surface. An external collector that holds AWS creds (a CI job, the customer's own script, or the gated
// SDK fetcher) POSTs the account's raw IAM + security-group + S3 state; the platform maps it
// (awsinventory.Build — grounded §10: trust edges only from real policies, internet-reach only when a SG
// actually opens the port) into the attack-path Inventory and STORES it as the tenant's cloud snapshot. So
// the AI Cloud Engineer (/v1/cloud/investigate), drift, and search reason over the REAL account state, not
// a hand-posted file — turning "find the attack path across all three" into a connected-account reality.
// Mirrors /v1/osint/ingest: the posted-snapshot path works today with no tsengine-side creds. The
// `?provider=` query selects the cloud (aws default | gcp | azure) — each maps its own raw shape through the
// matching grounded collector into the same cloudgraph.Inventory the engine reasons over.
//
// buildCloudInventory dispatches the posted raw cloud state to the right grounded collector by provider.
func buildCloudInventory(provider string, body []byte) (cloudgraph.Inventory, error) {
	switch provider {
	case "", "aws":
		var raw awsinventory.RawAWS
		if err := json.Unmarshal(body, &raw); err != nil {
			return cloudgraph.Inventory{}, fmt.Errorf("invalid AWS inventory body")
		}
		return awsinventory.Build(raw), nil
	case "gcp":
		var raw gcpinventory.RawGCP
		if err := json.Unmarshal(body, &raw); err != nil {
			return cloudgraph.Inventory{}, fmt.Errorf("invalid GCP inventory body")
		}
		return gcpinventory.Build(raw), nil
	case "azure":
		var raw azinventory.RawAzure
		if err := json.Unmarshal(body, &raw); err != nil {
			return cloudgraph.Inventory{}, fmt.Errorf("invalid Azure inventory body")
		}
		return azinventory.Build(raw), nil
	default:
		return cloudgraph.Inventory{}, fmt.Errorf("unknown provider %q (expected aws|gcp|azure)", provider)
	}
}

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
	inv, perr := buildCloudInventory(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider"))), body)
	if perr != nil {
		writeJSON(w, http.StatusBadRequest, errBody(perr.Error()))
		return
	}
	invJSON, err := json.Marshal(inv)
	if err != nil {
		respond(w, nil, err)
		return
	}
	// Diff-on-ingest (continuous Detect): if a prior snapshot exists, diff it against this fresh one BEFORE
	// overwriting → automatic cloud config-drift findings (a resource became public, a new privileged
	// principal, a new internet/privesc/lateral path). This makes cloud change-control CONTINUOUS on every
	// re-ingest — the "connect once, detect change" promise — with no separate /v1/cloud/drift call and no
	// live fetcher. Grounded + LLM-free (§10): an unchanged account yields zero findings; the first ingest
	// (no baseline) yields zero. Best-effort — a drift-diff failure never blocks storing the new snapshot.
	driftStored := 0
	if prevSnap, ok, gerr := d.CloudSnapshots.Get(r.Context(), tenantID); d.Store != nil && gerr == nil && ok && len(prevSnap.Inventory) > 0 {
		var prevInv cloudgraph.Inventory
		if json.Unmarshal(prevSnap.Inventory, &prevInv) == nil {
			findings := clouddrift.Diff(cloudgraph.Ingest(prevInv), cloudgraph.Ingest(inv), clouddrift.Options{})
			_, driftStored = d.persistDriftFindings(r.Context(), tenantID, findings)
		}
	}
	if err := d.CloudSnapshots.Put(r.Context(), cloudsnap.Snapshot{
		TenantID: tenantID, Inventory: invJSON, CapturedAt: time.Now().UTC(),
	}); err != nil {
		respond(w, nil, err)
		return
	}
	// CIEM: if the posted inventory's principals carry observed usage data, rightsize them into
	// over-privilege findings that flow through the same store/GRC/issues path. Inert (0 findings) when
	// no principal carries usage attrs — the honest gate (§10). Best-effort — never blocks the ingest.
	ciemStored := d.persistCIEMFindings(r.Context(), tenantID, cloudengine.RightsizePrincipals(cloudgraph.Ingest(inv)))
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
		"drift_detected": driftStored, // config changes vs the prior snapshot (0 on first ingest / no change)
		"ciem_findings":  ciemStored,  // over-privileged principals (0 unless the inventory carries usage data)
		"stored":         true,
	})
}

// persistCIEMFindings stores the CIEM over-privilege findings through the same L1.5-enrich → store → GRC
// path as drift findings (mirrors persistDriftFindings, with CIEM provenance). Best-effort.
func (d Deps) persistCIEMFindings(ctx context.Context, tenantID string, findings []types.Finding) int {
	if d.Store == nil || len(findings) == 0 {
		return 0
	}
	findings = enrichFindings(findings) // L1.5 parity (§11)
	saved := 0
	for i, f := range findings {
		f.ID = d.newID("ciem") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(ctx, tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(ctx, tenantID, f) // fold the least-privilege gap into the posture
		}
		saved++
	}
	if d.Recorder != nil && saved > 0 {
		d.Recorder.Record("ciem over-privilege detected", "ciem",
			map[string]any{"tenant_id": tenantID, "ciem_findings": saved}, "unused-permission rightsizing")
	}
	return saved
}
