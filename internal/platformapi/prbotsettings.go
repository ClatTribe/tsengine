package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// blockSeverities are the accepted merge-gating floors for the PR-review bot. "" / "off" = the
// bot comments but never fails the check-run (advisory); the others fail the check-run when a
// finding at/above that severity lands on PR-changed lines.
var blockSeverities = map[string]bool{"": true, "off": true, "critical": true, "high": true, "medium": true, "low": true}

// handleGetPRBotSettings returns the tenant's repository PR-review-bot policy (enabled +
// block-severity). No secret material; defaults to disabled when unset.
func (d Deps) handleGetPRBotSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	// Read through the SAME resolver the CI gate uses, so what a customer sees here is what their
	// pipeline actually does. These two used to decide independently what an unconfigured tenant
	// meant and disagreed: this view said "off" while the gate blocked merges.
	pol := d.resolvePRBotPolicy(r.Context(), tenantID)
	resp := map[string]any{"enabled": pol.Enabled, "block_severity": "off"}
	if pol.Enabled {
		resp["block_severity"] = string(pol.BlockAt)
	} else if t.PRBot != nil && t.PRBot.BlockSeverity != "" {
		// Keep showing a saved floor even while the gate is off, so toggling back on is predictable.
		resp["block_severity"] = t.PRBot.BlockSeverity
	}
	// Whether the live GitHub post is reachable is gated on a connected GitHub App with the PR
	// scope; surface that honestly so the UX can say "policy saved, posting needs GitHub".
	resp["github_connected"] = d.hasConnectionKind(r.Context(), tenantID, platform.ConnGitHub)
	// The three facts that decide whether a review actually lands in the PR, stated separately
	// because each has a different owner: the operator configures the App, the customer installs it
	// (the installation id), the customer connects GitHub. `posting_live` is their conjunction and
	// `not_posting_reason` names the first missing one.
	resp["app_configured"] = d.GitHubApp != nil
	resp["installation_id"] = ""
	if conn, ok := d.githubConnection(r.Context(), tenantID); ok {
		resp["installation_id"] = conn.Config[GitHubInstallationKey]
	}
	poster, reason := d.prPosterFor(r.Context(), tenantID)
	resp["posting_live"] = poster != nil
	resp["not_posting_reason"] = reason
	writeJSON(w, http.StatusOK, resp)
}

// handlePutPRBotSettings sets the PR-review-bot policy. Validates block_severity; ledger-recorded.
func (d Deps) handlePutPRBotSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Enabled       bool   `json:"enabled"`
		BlockSeverity string `json:"block_severity"`
		// InstallationID records where the GitHub App is installed (the numeric id GitHub shows
		// on the installation page). nil leaves it as it is; "" clears it.
		InstallationID *string `json:"installation_id,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	bs := strings.ToLower(strings.TrimSpace(body.BlockSeverity))
	if bs == "off" {
		bs = ""
	}
	if !blockSeverities[bs] {
		writeJSON(w, http.StatusBadRequest, errBody("block_severity must be one of: off, critical, high, medium, low"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	t.PRBot = &platform.PRBotPolicy{Enabled: body.Enabled, BlockSeverity: bs}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if body.InstallationID != nil {
		inst := strings.TrimSpace(*body.InstallationID)
		if inst != "" && !allDigits(inst) {
			writeJSON(w, http.StatusBadRequest, errBody("installation_id must be the numeric id GitHub shows on the App's installation page"))
			return
		}
		conn, ok := d.githubConnection(r.Context(), tenantID)
		if !ok {
			writeJSON(w, http.StatusBadRequest, errBody("connect GitHub before recording where the App is installed"))
			return
		}
		if conn.Config == nil {
			conn.Config = map[string]string{}
		}
		if inst == "" {
			delete(conn.Config, GitHubInstallationKey)
		} else {
			conn.Config[GitHubInstallationKey] = inst
		}
		if err := d.Store.PutConnection(r.Context(), conn); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
	}
	if d.Recorder != nil {
		d.Recorder.Record("PR-bot policy updated", "pr_bot_policy",
			map[string]any{"tenant_id": tenantID, "enabled": body.Enabled, "block_severity": bs},
			"repository PR-review-bot policy set")
	}
	out := bs
	if out == "" {
		out = "off"
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": body.Enabled, "block_severity": out, "saved": true})
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hasConnectionKind reports whether the tenant has a connection of the given kind (best-effort; a
// read error is treated as not-connected so the policy can still be saved).
func (d Deps) hasConnectionKind(ctx context.Context, tenantID, kind string) bool {
	conns, err := d.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return false
	}
	for _, c := range conns {
		if c.Kind == kind {
			return true
		}
	}
	return false
}
