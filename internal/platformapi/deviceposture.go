package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/ClatTribe/tsengine/internal/deviceposture"
	"github.com/ClatTribe/tsengine/pkg/types"
)

type deviceRequest struct {
	Devices []deviceposture.Device `json:"devices"`
}

// handleDevicePostureIngest is the ENDPOINT / DEVICE POSTURE ingest (MDM-lite) — the Vanta device-monitoring
// "finding issues" capability. A connector (or the customer) POSTs the device inventory; deviceposture.Assess
// surfaces grounded device-posture findings (unencrypted disk, end-of-life OS, jailbroken/tampered, no screen
// lock, firewall off, no EDR, auto-update off) into the same store, flowing through issues/incidents/grc/hitl.
// Grounded + LLM-free: a compliant fleet yields zero. A live MDM connector (Kandji/Jamf/Intune/Kolide) is the
// follow-on; the posted-inventory path works today (mirrors the OSINT/SaaS/tprm ingest).
func (d Deps) handleDevicePostureIngest(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var req deviceRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid device inventory: "+err.Error()))
		return
	}
	findings := deviceposture.Assess(req.Devices, deviceposture.Options{})
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("dev") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(r.Context(), tenantID, f)
		}
		saved = append(saved, f)
		stored++
	}
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("device posture assessed", "device_posture",
			map[string]any{"tenant_id": tenantID, "devices": len(req.Devices), "findings": stored}, "device-inventory ingest")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": len(req.Devices), "issues_detected": stored, "findings": findings})
}
