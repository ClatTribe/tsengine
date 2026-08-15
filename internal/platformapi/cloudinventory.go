package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/clouddrift"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudhistory"
	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/connector/azinventory"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
	"github.com/ClatTribe/tsengine/internal/connector/k8sinventory"
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
	case "kubernetes", "k8s":
		// The orchestrator is a cloud in its own right, and its security model is the SAME graph: a
		// ServiceAccount is a principal, a RoleBinding a grant, a pod runs-as its SA, an exposed Service
		// an internet edge, and the RBAC verbs that let one identity become another (bind / escalate /
		// impersonate / create-pods / read-secrets) are privesc edges. So it needed a fourth collector,
		// not a fourth engine — reachability, chaining, pruning and remediation all come for free.
		var raw k8sinventory.RawK8s
		if err := json.Unmarshal(body, &raw); err != nil {
			return cloudgraph.Inventory{}, fmt.Errorf("invalid Kubernetes inventory body")
		}
		return k8sinventory.Build(raw), nil
	default:
		return cloudgraph.Inventory{}, fmt.Errorf("unknown provider %q (expected aws|gcp|azure|kubernetes)", provider)
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
	// AN EMPTY INVENTORY IS REFUSED, NOT STORED.
	//
	// The FETCH path already refuses this exact case, in as many words: "an empty inventory would
	// read as an account with nothing in it". The posted path accepted it — POST {"account_id":"…"}
	// with nothing else returned stored:true, resources:0 — so the same danger the fetcher guards
	// against walked in through the other door.
	//
	// Two things go wrong once it is stored. The AI Cloud Engineer reasons over the snapshot, finds
	// no principals and no edges, and reports no attack paths for an account it has never seen.
	// And the snapshot becomes the DRIFT BASELINE, so the next real ingest diffs against "empty"
	// and reports every existing resource as newly created.
	//
	// A genuinely empty account loses nothing by this: there is nothing in it to analyse. A broken
	// collector gains a loud error instead of a silent clean bill.
	if len(inv.Resources) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "this inventory contains no resources, so it was not stored — an empty " +
				"inventory cannot be told apart from a collector that failed, and storing it would " +
				"both hide the account from the AI cloud engineer and make every real resource look " +
				"newly created on the next sync. Check the collector's output and post again.",
			"code": "empty_inventory",
		})
		return
	}
	invJSON, err := json.Marshal(inv)
	if err != nil {
		respond(w, nil, err)
		return
	}
	_, summary, aerr := d.applyCloudInventory(r.Context(), tenantID, inv, invJSON, "live AWS inventory collected → stored for the AI cloud engineer")
	if aerr != nil {
		respond(w, nil, aerr)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// applyCloudInventory is everything that happens to an inventory ONCE IT IS PARSED: drift-diff against
// the prior snapshot, store it, append the timeline, record the ledger entry, and summarise.
//
// Extracted so a LIVE fetch and a POSTED inventory travel the identical path. Two code paths that both
// "ingest an inventory" would drift — one would get drift-detection and the other would not, and the
// customer could not tell which they were looking at. Pure refactor: the posted path's behaviour is
// unchanged, which the existing handler tests hold us to.
//
// It returns the drift findings as well as the summary. They are already stored by the time this
// returns; the caller gets them so a SCHEDULED sync can fold them into the monitoring pass's view of
// present state. That matters: the reconciler RESOLVES any open incident whose finding is absent from
// that view, so drift findings which were stored but not handed back would be opened by
// persistDriftFindings and then immediately resolved by the same pass.
func (d Deps) applyCloudInventory(ctx context.Context, tenantID string, inv cloudgraph.Inventory, invJSON []byte, ledgerNote string) ([]types.Finding, map[string]any, error) {
	// Diff-on-ingest (continuous Detect): if a prior snapshot exists, diff it against this fresh one BEFORE
	// overwriting → automatic cloud config-drift findings (a resource became public, a new privileged
	// principal, a new internet/privesc/lateral path). This makes cloud change-control CONTINUOUS on every
	// re-ingest — the "connect once, detect change" promise. Grounded + LLM-free (§10): an unchanged
	// account yields zero findings; the first ingest (no baseline) yields zero. Best-effort — a drift-diff
	// failure never blocks storing the new snapshot.
	driftStored := 0
	var drift []types.Finding
	if prevSnap, ok, gerr := d.CloudSnapshots.Get(ctx, tenantID); d.Store != nil && gerr == nil && ok && len(prevSnap.Inventory) > 0 {
		var prevInv cloudgraph.Inventory
		if json.Unmarshal(prevSnap.Inventory, &prevInv) == nil {
			findings := clouddrift.Diff(cloudgraph.Ingest(prevInv), cloudgraph.Ingest(inv), clouddrift.Options{})
			drift, driftStored = d.persistDriftFindings(ctx, tenantID, findings)
		}
	}
	if err := d.CloudSnapshots.Put(ctx, cloudsnap.Snapshot{
		TenantID: tenantID, Inventory: invJSON, CapturedAt: time.Now().UTC(),
	}); err != nil {
		return nil, nil, err
	}
	// CAPTURE THE TIMELINE. Append-only, with change detection inside the store: an estate that has not
	// moved records nothing, so the history stays a record of CHANGE rather than one row per scan. This
	// is what turns "is this bucket public?" into "when did it become public?" — the first question asked
	// in an incident, and one the latest-wins snapshot store structurally could not answer.
	if d.CloudHistory != nil {
		dg := cloudhistory.DigestOf(cloudgraph.Ingest(inv), tenantID, inv.Provider, inv.AccountID, time.Now().UTC())
		_, _ = d.CloudHistory.Append(ctx, dg) // best-effort: history must never block the ingest
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
			ledgerNote)
	}
	return drift, map[string]any{
		"account_id":     inv.AccountID,
		"resources":      len(inv.Resources),
		"trust_edges":    len(inv.Trusts),
		"internet_edges": internetEdges,
		"drift_detected": driftStored, // config changes vs the prior snapshot (0 on first ingest / no change)
		"stored":         true,
	}, nil
}
