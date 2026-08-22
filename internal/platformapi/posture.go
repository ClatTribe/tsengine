package platformapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// markPostureAssessed stamps that a snapshot-driven posture source ran for this tenant. Called by each
// ingest handler AFTER a successful assess, regardless of how many findings came back — recording a
// CLEAN result is the whole point, since zero findings is otherwise indistinguishable from never
// having run. Best-effort: a store error must never fail an ingest that already succeeded.
func (d Deps) markPostureAssessed(ctx context.Context, tenantID, source string, at time.Time) {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return
	}
	if t.PostureAssessed == nil {
		t.PostureAssessed = map[string]time.Time{}
	}
	t.PostureAssessed[source] = at
	_ = d.Store.PutTenant(ctx, t)
}

// postureSources are the newer "asset-class posture" finding sources surfaced as first-class groups on the
// /posture view — the vendor portfolio, the employee device fleet, and cloud config-drift. Each is produced
// by a snapshot-driven assessor (tprm / deviceposture / clouddrift) and lands tool-tagged in the same store.
var postureSources = []struct{ Tool, Label, About string }{
	{"tprm", "Vendor risk", "Third-party / subprocessor risk: vendors handling your data without SOC 2 / a DPA / PCI, breach history, or overdue reviews."},
	{"deviceposture", "Device posture", "Employee endpoint risk: unencrypted disks, end-of-life OS, missing screen lock / firewall / EDR, tampered devices."},
	{"clouddrift", "Cloud drift", "Change-control: security-relevant cloud config changes since the last baseline (a resource became public, a new privileged principal, a new exposure path)."},
	{"sspm", "SaaS posture", "Configuration risk in the SaaS apps you run: org-wide 2FA, repo and file sharing, third-party app grants, guest and admin sprawl."},
	{"osint", "External exposure", "Your attacker's-eye footprint from open sources: leaked credentials and secrets, exposed hosts, typosquats, dangling DNS, certificate issues."},
}

// handlePostureView is the unified "posture sources" view (GET /v1/posture) — it makes the asset-class
// posture findings (vendor risk, device posture, cloud drift) first-class, grouped by source with a
// severity summary, instead of only mixed into the global issues list. The "in-depth analysis of the
// assets" one-stop-shop view for the asset classes a pure scanner misses. Optional ?source=tprm filter.
func (d Deps) handlePostureView(w http.ResponseWriter, r *http.Request, tenantID string) {
	all, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	want := strings.TrimSpace(r.URL.Query().Get("source"))

	byTool := map[string][]types.Finding{}
	for _, f := range all {
		byTool[f.Tool] = append(byTool[f.Tool], f)
	}

	// When each source last actually ran. Read from the tenant record because a grounded assessor
	// that finds nothing writes no findings — so the store alone cannot distinguish "assessed, clean"
	// from "never ingested", and the UI must not show the reassuring one for both.
	assessed := map[string]time.Time{}
	if t, err := d.Store.GetTenant(r.Context(), tenantID); err == nil {
		assessed = t.PostureAssessed
	}

	type sourceView struct {
		Key   string `json:"key"`
		Label string `json:"label"`
		About string `json:"about"`
		Count int    `json:"count"`
		// Assessed reports whether this source has EVER been ingested for this tenant. False with
		// Count 0 means not tested — not clean.
		Assessed   bool           `json:"assessed"`
		AssessedAt *time.Time     `json:"assessed_at,omitempty"`
		Severity   map[string]int `json:"severity"`

		Findings []types.Finding `json:"findings"`
	}
	sources := make([]sourceView, 0, len(postureSources))
	total := 0
	for _, s := range postureSources {
		if want != "" && want != s.Tool {
			continue
		}
		fs := byTool[s.Tool]
		sev := map[string]int{}
		for _, f := range fs {
			sev[string(f.Severity)]++
		}
		if fs == nil {
			fs = []types.Finding{}
		}
		view := sourceView{Key: s.Tool, Label: s.Label, About: s.About, Count: len(fs), Severity: sev, Findings: fs}
		if at, ok := assessed[s.Tool]; ok && !at.IsZero() {
			view.Assessed = true
			view.AssessedAt = &at
		} else if len(fs) > 0 {
			// Findings exist but predate the stamp (ingested before this field shipped). Their
			// existence IS proof the source ran, so report assessed without inventing a time.
			view.Assessed = true
		}
		sources = append(sources, view)
		total += len(fs)
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "sources": sources})
}
