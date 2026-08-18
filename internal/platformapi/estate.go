package platformapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/dataplatform"
	"github.com/ClatTribe/tsengine/internal/estatedetect"
	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/estateingest"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The estate graph in the platform: compose the tenant's surfaces into one typed graph, then run
// the cross-surface detections over it.
//
// This is the wiring that was missing. internal/estategraph and internal/estateingest were built
// and correct, but nothing composed them for a real tenant — so the cross-surface facts they make
// possible could not reach a customer. The findings produced here flow through the SAME path every
// other finding does (L1.5 enrichment → store → GRC posture → incidents), because a cross-surface
// finding is not a special artefact; it is a finding whose evidence happens to span two tools.

// composeEstate builds the tenant's estate graph from what is actually stored for them: the latest
// cloud inventory, and the leaked-secret findings that bridge code into it.
//
// Grounded (§10): every input is real stored state. A tenant with only one surface composes a
// one-surface graph, which detects no cross-surface joins — the honest result, not a hedge.
func (d Deps) composeEstate(ctx context.Context, tenantID string) (*estategraph.Graph, error) {
	return d.composeEstateWith(ctx, tenantID, nil, "")
}

// composeEstateWith is the general form, taking a warehouse estate the caller already holds.
//
// The warehouse is passed in rather than read back because nothing persists it: a grant snapshot
// arrives at its ingest, is assessed, and is gone. So the warehouse can only join the estate at the
// moment it is posted. That is a REAL limit, not a hedge — an agent composing the estate later will
// not see it — and it is stated here rather than papered over, because the alternative is a caller
// assuming warehouse context is always present. Persisting the snapshot is the follow-on that
// removes the caveat.
func (d Deps) composeEstateWith(ctx context.Context, tenantID string, wh *dataplatform.Estate, whRef string) (*estategraph.Graph, error) {
	var cloud *cloudgraph.Snapshot
	if d.CloudSnapshots != nil {
		if snap, ok, err := d.CloudSnapshots.Get(ctx, tenantID); err == nil && ok && len(snap.Inventory) > 0 {
			if inv, perr := cloudgraph.ParseInventory(snap.Inventory); perr == nil {
				cloud = cloudgraph.Ingest(inv)
			}
		}
	}
	// The code half of the bridge: findings whose own text carries a leaked key. FromLeakedSecrets
	// extracts it from the finding's evidence, never from the rule name.
	//
	// A caller may legitimately have no findings store — the cloud-inventory ingest is reachable
	// with only a snapshot store wired. Compose the cloud-only graph in that case: one surface
	// joins with nothing, which is the honest answer, and is emphatically better than panicking
	// inside an ingest handler.
	var findings []types.Finding
	if d.Store != nil {
		fs, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
		if err != nil {
			return nil, err
		}
		findings = fs
	}
	return estateingest.Compose(cloud, wh, whRef, findings, time.Now().UTC()), nil
}

// handleEstateGraph (GET /v1/estate) returns the composed graph — the substrate itself, so an
// operator can see what the agents reason over rather than inferring it from findings.
func (d Deps) handleEstateGraph(w http.ResponseWriter, r *http.Request, tenantID string) {
	g, err := d.composeEstate(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	surfaces := map[string]int{}
	bridges := 0
	for _, n := range g.Nodes {
		for _, s := range n.Surfaces {
			surfaces[s]++
		}
		if len(n.Surfaces) > 1 {
			bridges++ // a node two surfaces both assert — the join itself
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": g.Nodes, "edges": g.Edges,
		"node_count": len(g.Nodes), "edge_count": len(g.Edges),
		"surfaces": surfaces,
		// Surfaced deliberately: with fewer than two surfaces there is nothing to join, and the
		// reader should see that rather than wonder why no cross-surface findings appeared.
		"cross_surface_nodes": bridges,
		"joinable":            len(surfaces) >= 2,
	})
}

// handleEstateDetect (POST /v1/estate/detect) composes the graph, runs the cross-surface
// detections, and persists what it finds through the normal pipeline.
func (d Deps) handleEstateDetect(w http.ResponseWriter, r *http.Request, tenantID string) {
	g, err := d.composeEstate(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	found := estatedetect.Detect(g, estatedetect.Options{Now: time.Now().UTC()})
	saved := d.persistEstateFindings(r.Context(), tenantID, found)
	if saved == nil {
		saved = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": saved, "count": len(saved),
		"node_count": len(g.Nodes), "edge_count": len(g.Edges),
	})
}

// persistEstateFindings runs the batch through the same L1.5 chain, store, GRC and incident path
// as every other ingest (§11 parity) — a cross-surface finding must not be a second-class citizen
// that skips enrichment and never reaches the approval desk.
func (d Deps) persistEstateFindings(ctx context.Context, tenantID string, findings []types.Finding) []types.Finding {
	if len(findings) == 0 {
		return nil
	}
	findings = enrichFindings(findings)
	saved := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		// A STABLE, content-derived id, because this runs on every pass that changes a surface. One
		// cross-surface fact must be ONE finding: a freshly-minted id per pass files a new copy of a
		// problem the customer already has, and makes "how many issues do I have" a function of how
		// often we looked rather than of the estate. PutFinding upserts by id, so re-detecting the
		// same fact updates the row instead of adding one.
		f.ID = estateFindingID(f)
		if err := d.Store.PutFinding(ctx, tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(ctx, tenantID, f)
		}
		saved = append(saved, f)
	}
	if d.IncidentOpener != nil && len(saved) > 0 {
		_, _ = d.IncidentOpener.OpenFor(ctx, tenantID, saved, nil)
	}
	if d.Recorder != nil && len(saved) > 0 {
		d.Recorder.Record("cross-surface findings detected", "estate_graph",
			map[string]any{"tenant_id": tenantID, "findings": len(saved)},
			"joins across surfaces no single scanner can see")
	}
	return saved
}

// estateOrNil composes the tenant's estate graph for an agent run, or returns nil.
//
// Best-effort ON PURPOSE: the cloud investigation is valuable with or without the cross-surface
// view, so a compose failure must degrade the agent's reach rather than fail its run. nil is a
// state estate_context handles honestly — it reports the graph as unavailable rather than as
// empty, so the agent never concludes "nothing else touches this" from a compose error.
func (d Deps) estateOrNil(ctx context.Context, tenantID string) *estategraph.Graph {
	g, err := d.composeEstate(ctx, tenantID)
	if err != nil || g == nil || len(g.Nodes) == 0 {
		return nil
	}
	return g
}

// detectEstateOnIngest re-runs the cross-surface detections after a surface changed, and persists
// what it finds. Best-effort: it returns nil on any failure rather than propagating, because the
// ingest that triggered it must succeed regardless of whether the join produced anything.
//
// Idempotent in effect: the detections are derived from current state, so an unchanged estate
// produces the same findings, and the incident reconciler keys on rule+endpoint rather than
// finding id — a re-ingest refreshes an existing incident instead of opening a duplicate.
func (d Deps) detectEstateOnIngest(ctx context.Context, tenantID string) []types.Finding {
	return d.detectEstateOnIngestWith(ctx, tenantID, nil, "")
}

// detectEstateOnIngestWith runs cross-surface detection with a warehouse estate the caller holds.
func (d Deps) detectEstateOnIngestWith(ctx context.Context, tenantID string, wh *dataplatform.Estate, whRef string) []types.Finding {
	g, err := d.composeEstateWith(ctx, tenantID, wh, whRef)
	if err != nil || g == nil || len(g.Nodes) == 0 {
		return nil
	}
	found := estatedetect.Detect(g, estatedetect.Options{Now: time.Now().UTC()})
	if len(found) == 0 {
		return nil // only one surface, or nothing joins — the honest result
	}
	return d.persistEstateFindings(ctx, tenantID, found)
}

// estateFindingID derives a finding's id from what it asserts — its rule and the node it is about.
// Those two are exactly what makes a cross-surface fact the same fact across passes, and they are
// also what detect.Reconcile keys an incident on, so a finding and its incident stay in step.
func estateFindingID(f types.Finding) string {
	sum := sha256.Sum256([]byte(f.RuleID + "|" + f.Endpoint))
	return "estate::" + hex.EncodeToString(sum[:8])
}

// DetectEstateEachPass is the runner.Service.AfterPass hook for cross-surface detection.
//
// WHY A PASS-LEVEL HOOK AND NOT PER-INGEST. A cross-surface finding needs two surfaces, and the
// second one can arrive through any of a dozen ingest handlers — or through a scan, which is not an
// ingest at all. Wiring each door means the next door added silently does not join, which is how the
// identity join shipped reachable only by tenants who happened to re-post a cloud inventory
// afterwards. The cloud and warehouse ingests still detect inline for immediate feedback; this hook
// is what makes the join eventually found regardless of how its halves arrived.
//
// Affordable to run unconditionally: the detections are deterministic and LLM-free, so unlike the
// auto-review there is no budget to gate. Best-effort — a compose failure must never disturb a
// monitoring pass.
func (d Deps) DetectEstateEachPass(ctx context.Context, tenantID string) {
	if d.Store == nil {
		return
	}
	_ = d.detectEstateOnIngest(ctx, tenantID)
}
