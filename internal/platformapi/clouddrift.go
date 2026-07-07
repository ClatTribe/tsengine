package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/ClatTribe/tsengine/internal/clouddrift"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// driftRequest carries the two cloud inventory snapshots to compare: prev (the approved baseline / last
// scan) and cur (now). Both are normalized cloudgraph inventories (the same shape ingest sources emit).
type driftRequest struct {
	Prev cloudgraph.Inventory `json:"prev"`
	Cur  cloudgraph.Inventory `json:"cur"`
}

// handleCloudDrift is the CONTINUOUS DRIFT-DETECTION ingest — the config-snapshot-diff half of cloud
// drift (cloudcdr does audit-log drift; detect does finding-diff drift). A connector (or the customer)
// POSTs the previous + current cloud inventory; clouddrift.Diff surfaces the security-relevant config
// changes (a resource became public, a new privileged principal, a new internet/privesc/lateral path) and
// they land in the SAME store as every finding — flowing through issues / incidents / grc / hitl as the
// SOC2/CIS change-control signal. Grounded + LLM-free: an unchanged pair yields zero findings.
//
// Live continuous wiring (persist each tenant's last snapshot, diff on every scan) is the platform
// follow-on; this posted-snapshots path works today, mirroring the OSINT / SaaS-posture ingest.
func (d Deps) handleCloudDrift(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var req driftRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid drift request: "+err.Error()))
		return
	}

	prev := cloudgraph.Ingest(req.Prev)
	cur := cloudgraph.Ingest(req.Cur)
	findings := clouddrift.Diff(prev, cur, clouddrift.Options{})
	saved, stored := d.persistDriftFindings(r.Context(), tenantID, findings)
	if saved == nil {
		saved = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"drift_detected": stored, "findings": saved})
}

// persistDriftFindings enriches (L1.5 parity §11), stores, folds into the GRC posture, and — for a
// high-severity drift (became-public / new-privileged / new-internet-exposure) — opens an incident, for a
// batch of cloud-drift findings. Shared by the explicit /v1/cloud/drift ingest AND the automatic
// diff-on-ingest path (cloudinventory.go) so the two never diverge. Returns the stored findings (with
// assigned ids) + the count. Grounded + LLM-free: an unchanged account produces an empty batch → no-op.
func (d Deps) persistDriftFindings(ctx context.Context, tenantID string, findings []types.Finding) ([]types.Finding, int) {
	findings = enrichFindings(findings) // L1.5 parity (§11)
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("drift") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(ctx, tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(ctx, tenantID, f) // fold the change-control finding into the posture
		}
		saved = append(saved, f)
	}
	if d.IncidentOpener != nil && len(saved) > 0 {
		_, _ = d.IncidentOpener.OpenFor(ctx, tenantID, saved, nil)
	}
	if d.Recorder != nil && len(saved) > 0 {
		d.Recorder.Record("cloud drift detected", "cloud_drift",
			map[string]any{"tenant_id": tenantID, "drift_findings": len(saved)}, "config-snapshot drift")
	}
	return saved, len(saved)
}
