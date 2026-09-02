package platformapi

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"strings"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// hasAnyFinding reports whether the tenant has at least one stored finding. Limit 1: this is a
// yes/no, and a workspace that imported a scanner backlog is not small.
func (d Deps) hasAnyFinding(ctx context.Context, tenantID string) bool {
	fs, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{Limit: 1})
	return err == nil && len(fs) > 0
}

// notifyFirstFindings emails the workspace owners the moment the FIRST findings land — the
// activation event the whole free tier is optimised for, and until now the one nobody was told
// about. The person who connected GitHub and closed the tab learns that the scan finished and
// found something only if they come back and look; this is the message that brings them back.
//
// Sent ONCE, structurally: only when the tenant had no findings before this scan and has some
// after. Every later scan is monitoring, and monitoring has its own channels (incidents, Slack).
// Same gate as every other transactional mail — a configured Mailer, else a log line — and a
// send failure is logged, never surfaced to the scan: the findings are stored either way.
func (d Deps) notifyFirstFindings(ctx context.Context, tenantID, kindLabel string, hadFindingsBefore bool) {
	if hadFindingsBefore || !d.hasAnyFinding(ctx, tenantID) {
		return
	}
	if d.Mailer == nil || !d.Mailer.Configured() {
		slog.Info("first findings landed (no mailer configured, not emailed)", "tenant", tenantID, "via", kindLabel)
		return
	}
	users, err := d.Store.ListUsers(ctx, tenantID)
	if err != nil {
		return
	}
	link := strings.TrimRight(d.AppURL, "/") + "/issues"
	esc := html.EscapeString
	body := fmt.Sprintf(
		"<p>The first scan of the %s you connected has finished, and it found something.</p>"+
			"<p><a href=\"%s\">Review your findings</a> — each one says what was found, where, the evidence behind it, and the fix.</p>"+
			"<p>From here the workspace keeps watching; you will hear about new high-severity findings as incidents, not as email.</p>",
		esc(kindLabel), esc(link))
	for _, u := range users {
		if u.Role != platform.RoleOwner || u.Email == "" {
			continue
		}
		if err := d.Mailer.Send(ctx, u.Email, "Your first findings are in", body); err != nil {
			slog.Warn("first-findings email failed", "tenant", tenantID, "to", u.Email, "err", err)
		}
	}
}
