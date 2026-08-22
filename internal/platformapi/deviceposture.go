package platformapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	findings = enrichFindings(findings) // L1.5 parity (§11)
	// Record that the fleet was assessed — a compliant fleet yields zero findings, which must not
	// read the same as never having checked.
	d.markPostureAssessed(r.Context(), tenantID, "deviceposture", time.Now().UTC())
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("dev") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		d.foldIntoPosture(r.Context(), tenantID, []types.Finding{f})
		saved = append(saved, f)
		stored++
	}
	// Findings that arrive by ingest reach the approval desk too — the same remediate.Propose
	// the runner uses for engine-scanned findings. Nil ProposeFix/Submitter → no-op.
	d.proposeForFindings(r.Context(), tenantID, saved)
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
	resp := map[string]any{"devices": len(req.Devices), "issues_detected": stored, "findings": findings}
	// Say how many devices we could not read, rather than letting a silent skip read as a clean fleet.
	// "0 issues over 2 devices" is a compliance claim about disk encryption; if the export did not name
	// the devices we assessed none of them, and that has to be visible here (§10).
	names := make([]string, 0, len(req.Devices))
	for _, dv := range req.Devices {
		names = append(names, dv.Name)
	}
	notes := ingestNotes(len(req.Devices), countNamed(names), "device", "devices",
		"they did not carry a device name")
	// The same reasoning one level down: a device can be READ and still not report a given setting.
	// Those settings are no longer treated as "off" (they used to be, which manufactured findings from
	// missing data), so the silence has to be said out loud — otherwise "0 issues" reads as "firewalls
	// are on" when the export never mentioned firewalls.
	if note := unreportedSettingsNote(req.Devices); note != "" {
		notes = append(notes, note)
	}
	if len(notes) > 0 {
		resp["checks_not_run"] = notes
	}
	writeJSON(w, http.StatusOK, resp)
}

// unreportedSettingsNote names the protective settings the export did not carry, and how many
// devices were silent on each. Grounded (§10): it counts real absences and claims nothing about what
// those settings actually are.
func unreportedSettingsNote(devices []deviceposture.Device) string {
	type gap struct {
		label string
		count int
	}
	gaps := []gap{
		{"disk encryption", 0}, {"screen lock", 0}, {"host firewall", 0},
		{"EDR / antivirus", 0}, {"automatic updates", 0},
	}
	for _, dv := range devices {
		for i, present := range []bool{
			dv.DiskEncrypted != nil, dv.ScreenLock != nil, dv.FirewallOn != nil,
			dv.EDR != nil, dv.AutoUpdate != nil,
		} {
			if !present {
				gaps[i].count++
			}
		}
	}
	var parts []string
	for _, g := range gaps {
		if g.count > 0 {
			parts = append(parts, fmt.Sprintf("%s (%d)", g.label, g.count))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "These settings were not reported by every device, so they were not assessed: " +
		strings.Join(parts, ", ") + ". A setting your export omits is unknown, not compliant — check " +
		"the field names in your MDM export."
}
