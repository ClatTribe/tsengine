package platformapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
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
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil, err
	}
	return estateingest.Compose(cloud, nil, "", findings, time.Now().UTC()), nil
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
	for i, f := range findings {
		f.ID = d.newID("estate") + "-" + strconv.Itoa(i)
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
