package platformapi

import (
	"context"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// findingView is a finding plus its transient impact annotation for the report surface (the /findings list):
// whether it sits on a chain reaching a crown jewel (how big it can get). Embeds the finding so every native
// field is preserved; blast_radius is added, omitempty so a contained finding looks unchanged.
type findingView struct {
	types.Finding
	BlastRadius *platform.BlastRadius `json:"blast_radius,omitempty"`
}

// annotateFindingsImpact wraps each finding with its blast radius (read-time, from the correlate chains —
// the same as /attack-paths). Best-effort: an assets fetch error just yields un-annotated views.
func (d Deps) annotateFindingsImpact(ctx context.Context, tenantID string, findings []types.Finding) []findingView {
	var br map[string]platform.BlastRadius
	if assets, err := d.Store.ListAssets(ctx, tenantID); err == nil {
		br = crossdetect.BlastRadiusByFinding(assets, findings)
	}
	out := make([]findingView, len(findings))
	for i := range findings {
		out[i] = findingView{Finding: findings[i]}
		if r, ok := br[findings[i].ID]; ok {
			rr := r
			out[i].BlastRadius = &rr
		}
	}
	return out
}

// annotateBlastRadius stamps each incident with a TRANSIENT, read-time impact signal — whether its finding
// sits on a cross-surface chain reaching a crown jewel (how big it can get). Computed from the correlate
// chains (the same as /attack-paths), never persisted. Tenant-scoped + best-effort: a fetch error leaves
// the incidents un-annotated (impact then reads as just severity), never failing the list.
func (d Deps) annotateBlastRadius(ctx context.Context, tenantID string, incs []platform.Incident) {
	if len(incs) == 0 {
		return
	}
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return
	}
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return
	}
	br := crossdetect.BlastRadiusByFinding(assets, findings)
	for i := range incs {
		if r, ok := br[incs[i].FindingID]; ok {
			rr := r
			incs[i].BlastRadius = &rr
		}
	}
}

// handleSecurityByAsset returns the per-asset security posture — the "is THIS asset secure?" view a
// daily-driver user needs. Tenant-scoped (§18.2 inv. 2): reads only this tenant's assets + findings +
// engagements. Grounded + FP-aware (§10): crossdetect.AssetSecurityPosture attributes a finding to an
// asset only when the asset's Target appears in the finding endpoint, separates confirmed
// (verified/corroborated) from unconfirmed (pattern_match) so a wall of low-confidence noise never reads
// as urgent, and never claims a bare "secure" — a scanned-clean asset is "no issues found in the last
// scan", an un-scanned one says so.
func (d Deps) handleSecurityByAsset(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	// scan-coverage: an asset is "scanned" once it has at least one completed engagement.
	scanned := map[string]bool{}
	if engs, err := d.Store.ListEngagements(ctx, tenantID); err == nil {
		for _, e := range engs {
			if !e.CompletedAt.IsZero() {
				scanned[e.AssetID] = true
			}
		}
	}
	posture := crossdetect.AssetSecurityPosture(assets, findings, scanned)
	atRisk := 0
	for _, p := range posture {
		if p.Confirmed > 0 && (p.Critical+p.High) > 0 {
			atRisk++
		}
	}
	respond(w, map[string]any{"assets": posture, "total": len(posture), "at_risk": atRisk}, nil)
}
