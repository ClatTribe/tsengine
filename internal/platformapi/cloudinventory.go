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
	"github.com/ClatTribe/tsengine/internal/connector"
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
func buildCloudInventory(provider string, body []byte) (cloudgraph.Inventory, connector.InventoryCoverage, error) {
	switch provider {
	case "", "aws":
		var raw awsinventory.RawAWS
		if err := json.Unmarshal(body, &raw); err != nil {
			return cloudgraph.Inventory{}, connector.InventoryCoverage{}, fmt.Errorf("invalid AWS inventory body")
		}
		return awsinventory.Build(raw), connector.CoverAWS(raw), nil
	case "gcp":
		var raw gcpinventory.RawGCP
		if err := json.Unmarshal(body, &raw); err != nil {
			return cloudgraph.Inventory{}, connector.InventoryCoverage{}, fmt.Errorf("invalid GCP inventory body")
		}
		return gcpinventory.Build(raw), connector.CoverGCP(raw), nil
	case "azure":
		var raw azinventory.RawAzure
		if err := json.Unmarshal(body, &raw); err != nil {
			return cloudgraph.Inventory{}, connector.InventoryCoverage{}, fmt.Errorf("invalid Azure inventory body")
		}
		// No coverage analyser yet: Azure reports nothing rather than claiming completeness
		// it has not checked.
		return azinventory.Build(raw), connector.InventoryCoverage{}, nil
	case "kubernetes", "k8s":
		// The orchestrator is a cloud in its own right, and its security model is the SAME graph: a
		// ServiceAccount is a principal, a RoleBinding a grant, a pod runs-as its SA, an exposed Service
		// an internet edge, and the RBAC verbs that let one identity become another (bind / escalate /
		// impersonate / create-pods / read-secrets) are privesc edges. So it needed a fourth collector,
		// not a fourth engine — reachability, chaining, pruning and remediation all come for free.
		var raw k8sinventory.RawK8s
		if err := json.Unmarshal(body, &raw); err != nil {
			return cloudgraph.Inventory{}, connector.InventoryCoverage{}, fmt.Errorf("invalid Kubernetes inventory body")
		}
		return k8sinventory.Build(raw), connector.InventoryCoverage{}, nil
	default:
		return cloudgraph.Inventory{}, connector.InventoryCoverage{}, fmt.Errorf("unknown provider %q (expected aws|gcp|azure|kubernetes)", provider)
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
	inv, coverage, perr := buildCloudInventory(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider"))), body)
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
	// CI/FEDERATED-IDENTITY ASSESSMENT. The posted inventory carries each role's trust policy, which is
	// the entire access-control decision for a workflow reaching this account with no stored credential.
	// internal/ghoidc analyses exactly that and had no caller, so the surface was invisible in precisely
	// the way that motivated building it. Runs before the store call so its findings ride the same
	// enrich → store → issues/incidents path as drift.
	ciFindings, ciNotAssessed := ciIdentityAssess(
		strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider"))), body)
	// THE JOIN (ADR 0024 Sprint 2). ghoidc says a trust is over-broad; the provider dry-run says what
	// that role can then REACH. Separately each is deferrable — plenty of broadly-trusted roles hold
	// nothing — and together they are the finding, so the reach ANNOTATES the existing weakness rather
	// than splitting one fact across two rows. No prober, no declared crown jewel, or a correctly
	// scoped trust → the findings pass through untouched.
	ciFindings = annotateCIReach(r.Context(), rawAWSOrEmpty(body), ciFindings, d.proberOrNil(r.Context(), tenantID))
	_, ciStored := d.persistCIIdentityFindings(r.Context(), tenantID, ciFindings)
	// WHAT THE CI-IDENTITY CHECK COULD NOT LOOK AT rides into the STORED coverage notes, next to the
	// escalation gaps, for the reason those are stored: the reader of the attack-path page is rarely
	// the CI job that posted the inventory. A role assumable by an Okta or other SAML provider we do
	// not model is exactly what these declarations name, and dropping them here left the estate
	// looking like one that federates through nothing.
	if len(ciNotAssessed) > 0 {
		if coverage.Notes == nil {
			coverage.Notes = map[string]string{}
		}
		for k, v := range ciNotAssessed {
			coverage.Notes[k] = v
		}
	}
	_, summary, aerr := d.applyCloudInventoryWithCoverage(r.Context(), tenantID, inv, invJSON,
		"live AWS inventory collected → stored for the AI cloud engineer", coverage)
	if aerr != nil {
		respond(w, nil, aerr)
		return
	}
	// WHAT THIS SNAPSHOT COULD NOT ANSWER rides back with the result.
	//
	// The live fetch path has said this since it was written — "silence about coverage is how a
	// partial picture passes for a whole one" — but the POSTED path bypasses it, and posting is how
	// GCP arrives at all. The specific danger is escalation: it is computed from policy documents
	// (AWS) and IAM bindings (GCP), and a snapshot omitting them yields exactly zero escalation
	// edges. "Nobody can become admin in your account" is the most reassuring thing this product can
	// say and the most damaging thing to say wrongly.
	summary["coverage"] = coverage.Summary()
	// Reported so the poster can see the CI-trust surface was assessed at all. Zero is a real answer
	// here — most roles are not federated — and it is reported as a count rather than omitted, so
	// "assessed, nothing wrong" is distinguishable from "never ran".
	summary["ci_identity_findings"] = ciStored
	if !coverage.Complete() {
		summary["coverage_gaps"] = coverage.Notes
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
	return d.applyCloudInventoryWithCoverage(ctx, tenantID, inv, invJSON, ledgerNote, connector.InventoryCoverage{})
}

// applyCloudInventoryWithCoverage is applyCloudInventory carrying what the snapshot could
// not answer, so the gap is STORED alongside it rather than only returned to whoever
// posted it. The reader of the attack-path page is rarely the CI job that posted the
// inventory, and they are the one who needs to know the escalation analysis was partial.
func (d Deps) applyCloudInventoryWithCoverage(ctx context.Context, tenantID string, inv cloudgraph.Inventory, invJSON []byte, ledgerNote string, coverage connector.InventoryCoverage) ([]types.Finding, map[string]any, error) {
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
		CoverageGaps: coverage.Notes,
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

	// CROSS-SURFACE DETECTION ON INGEST. The cloud half of the estate has just changed, so re-run the
	// joins against everything else we hold for this tenant — a key leaked in code becomes an incident
	// the moment the cloud account it unlocks is ingested, without waiting for anyone to ask.
	//
	// Placed AFTER the snapshot Put on purpose: composeEstate reads the STORED inventory, so running it
	// earlier would join against the previous cloud state and miss exactly the change that triggered it.
	// Best-effort — a detection failure must never block storing the inventory.
	estateFindings := d.detectEstateOnIngest(ctx, tenantID)
	// Returned alongside drift for the same reason drift is: the monitoring pass RESOLVES any open
	// incident whose finding is absent from the present-state view it is handed, so findings stored here
	// but not handed back would be opened and immediately resolved by the same pass.
	drift = append(drift, estateFindings...)

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
		"account_id":             inv.AccountID,
		"resources":              len(inv.Resources),
		"trust_edges":            len(inv.Trusts),
		"internet_edges":         internetEdges,
		"drift_detected":         driftStored,         // config changes vs the prior snapshot (0 on first ingest / no change)
		"cross_surface_detected": len(estateFindings), // joins with other surfaces (0 when only cloud is connected)
		"stored":                 true,
	}, nil
}
