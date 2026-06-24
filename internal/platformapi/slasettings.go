package platformapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// slasettings.go is the per-tenant remediation SLA policy (per-severity time-to-acknowledge +
// time-to-resolve targets) — the managed-security promise the AAI-PO "24x7 SOC" implies and every
// MDR / vuln-mgmt competitor ships. No secret material (severity + hours only), so it stores plain
// on the Tenant like the escalation matrix and the PR-bot policy.

var slaSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}

// handleGetSLASettings returns the tenant's SLA policy; defaults to a disabled empty policy.
func (d Deps) handleGetSLASettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	pol := t.SLA
	if pol == nil {
		pol = &platform.SLAPolicy{Targets: []platform.SLATarget{}}
	}
	if pol.Targets == nil {
		pol.Targets = []platform.SLATarget{}
	}
	writeJSON(w, http.StatusOK, pol)
}

// handlePutSLASettings validates + stores the tenant's SLA policy. Each target's severity must be
// known, hours must be ≥ 0, and a severity may appear at most once. Ledger-recorded.
func (d Deps) handlePutSLASettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Enabled bool `json:"enabled"`
		Targets []struct {
			Severity     string `json:"severity"`
			AckHours     int    `json:"ack_hours"`
			ResolveHours int    `json:"resolve_hours"`
		} `json:"targets"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	seen := map[string]bool{}
	targets := make([]platform.SLATarget, 0, len(body.Targets))
	for i, tg := range body.Targets {
		sev := strings.ToLower(strings.TrimSpace(tg.Severity))
		if !slaSeverities[sev] {
			writeJSON(w, http.StatusBadRequest, errBody("target "+strconv.Itoa(i)+": severity must be one of: critical, high, medium, low"))
			return
		}
		if seen[sev] {
			writeJSON(w, http.StatusBadRequest, errBody("target "+strconv.Itoa(i)+": duplicate severity "+sev))
			return
		}
		if tg.AckHours < 0 || tg.ResolveHours < 0 {
			writeJSON(w, http.StatusBadRequest, errBody("target "+strconv.Itoa(i)+": hours must be ≥ 0"))
			return
		}
		if tg.AckHours == 0 && tg.ResolveHours == 0 {
			writeJSON(w, http.StatusBadRequest, errBody("target "+strconv.Itoa(i)+": set at least one of ack_hours / resolve_hours"))
			return
		}
		seen[sev] = true
		targets = append(targets, platform.SLATarget{Severity: sev, AckHours: tg.AckHours, ResolveHours: tg.ResolveHours})
	}
	// Enabling with no targets is a no-op "on" — reject so the UX can't save one.
	if body.Enabled && len(targets) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("an enabled SLA policy needs at least one target"))
		return
	}

	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	t.SLA = &platform.SLAPolicy{Enabled: body.Enabled, Targets: targets}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("sla policy updated", "sla_policy",
			map[string]any{"tenant_id": tenantID, "enabled": body.Enabled, "targets": len(targets)},
			"remediation SLA policy set")
	}
	writeJSON(w, http.StatusOK, t.SLA)
}
