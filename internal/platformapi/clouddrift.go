package platformapi

import (
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

	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("drift") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(r.Context(), tenantID, f) // fold the change-control finding into the posture
		}
		saved = append(saved, f)
		stored++
	}
	// a high-severity drift (became-public, new-privileged, new-internet-exposure) is incident-worthy now.
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("cloud drift detected", "cloud_drift",
			map[string]any{"tenant_id": tenantID, "drift_findings": stored}, "config-snapshot drift")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"drift_detected": stored, "findings": findings})
}
