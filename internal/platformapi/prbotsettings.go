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
	resp := map[string]any{"enabled": false, "block_severity": "off"}
	if t.PRBot != nil {
		resp["enabled"] = t.PRBot.Enabled
		bs := t.PRBot.BlockSeverity
		if bs == "" {
			bs = "off"
		}
		resp["block_severity"] = bs
	}
	// Whether the live GitHub post is reachable is gated on a connected GitHub App with the PR
	// scope; surface that honestly so the UX can say "policy saved, posting needs GitHub".
	resp["github_connected"] = d.hasConnectionKind(r.Context(), tenantID, platform.ConnGitHub)
	writeJSON(w, http.StatusOK, resp)
}

// handlePutPRBotSettings sets the PR-review-bot policy. Validates block_severity; ledger-recorded.
func (d Deps) handlePutPRBotSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Enabled       bool   `json:"enabled"`
		BlockSeverity string `json:"block_severity"`
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
