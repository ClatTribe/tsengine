package platformapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// escalationsettings.go is the per-tenant incident escalation matrix (Phase 1 of the MDR/SOC
// escalation gap — the "who is alerted, how urgently" config the autonomous SOC needs, at par with
// PagerDuty/Opsgenie and the contractual "escalation matrix with contact number"). No secret
// material — channel names only — so it's stored plain on the Tenant (like the PR-bot policy).

var escalationChannels = map[string]bool{"slack": true, "pagerduty": true, "teams": true, "discord": true, "email": true, "webhook": true}
var escalationSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}

// handleGetEscalationSettings returns the tenant's escalation policy (enabled + ack window + tiers);
// defaults to a disabled empty policy when unset.
func (d Deps) handleGetEscalationSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	pol := t.Escalation
	if pol == nil {
		pol = &platform.EscalationPolicy{Tiers: []platform.EscalationTier{}}
	}
	if pol.Tiers == nil {
		pol.Tiers = []platform.EscalationTier{}
	}
	writeJSON(w, http.StatusOK, pol)
}

// handlePutEscalationSettings validates + stores the tenant's escalation matrix. Each tier's
// min_severity must be a known severity and every channel a known notify channel; ledger-recorded.
func (d Deps) handlePutEscalationSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Enabled       bool `json:"enabled"`
		AckWindowMins int  `json:"ack_window_mins"`
		Tiers         []struct {
			MinSeverity string   `json:"min_severity"`
			Channels    []string `json:"channels"`
		} `json:"tiers"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if body.AckWindowMins < 0 {
		writeJSON(w, http.StatusBadRequest, errBody("ack_window_mins must be ≥ 0"))
		return
	}
	tiers := make([]platform.EscalationTier, 0, len(body.Tiers))
	for i, tier := range body.Tiers {
		sev := strings.ToLower(strings.TrimSpace(tier.MinSeverity))
		if !escalationSeverities[sev] {
			writeJSON(w, http.StatusBadRequest, errBody("tier "+strconv.Itoa(i)+": min_severity must be one of: critical, high, medium, low"))
			return
		}
		chans := make([]string, 0, len(tier.Channels))
		for _, c := range tier.Channels {
			c = strings.ToLower(strings.TrimSpace(c))
			if !escalationChannels[c] {
				writeJSON(w, http.StatusBadRequest, errBody("tier "+strconv.Itoa(i)+": unknown channel "+c+" (want: slack, pagerduty, teams, discord, email, webhook)"))
				return
			}
			chans = append(chans, c)
		}
		if len(chans) == 0 {
			writeJSON(w, http.StatusBadRequest, errBody("tier "+strconv.Itoa(i)+": at least one channel is required"))
			return
		}
		tiers = append(tiers, platform.EscalationTier{MinSeverity: sev, Channels: chans})
	}
	// Enabling with no tiers is meaningless — reject so the UX can't save a no-op "on" policy.
	if body.Enabled && len(tiers) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("an enabled policy needs at least one tier"))
		return
	}

	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	t.Escalation = &platform.EscalationPolicy{Enabled: body.Enabled, AckWindowMins: body.AckWindowMins, Tiers: tiers}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("escalation policy updated", "escalation_policy",
			map[string]any{"tenant_id": tenantID, "enabled": body.Enabled, "tiers": len(tiers)},
			"incident escalation matrix set")
	}
	writeJSON(w, http.StatusOK, t.Escalation)
}
