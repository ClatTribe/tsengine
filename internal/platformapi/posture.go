package platformapi

import (
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// postureSources are the newer "asset-class posture" finding sources surfaced as first-class groups on the
// /posture view — the vendor portfolio, the employee device fleet, and cloud config-drift. Each is produced
// by a snapshot-driven assessor (tprm / deviceposture / clouddrift) and lands tool-tagged in the same store.
var postureSources = []struct{ Tool, Label, About string }{
	{"tprm", "Vendor risk", "Third-party / subprocessor risk: vendors handling your data without SOC 2 / a DPA / PCI, breach history, or overdue reviews."},
	{"deviceposture", "Device posture", "Employee endpoint risk: unencrypted disks, end-of-life OS, missing screen lock / firewall / EDR, tampered devices."},
	{"clouddrift", "Cloud drift", "Change-control: security-relevant cloud config changes since the last baseline (a resource became public, a new privileged principal, a new exposure path)."},
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

	type sourceView struct {
		Key      string          `json:"key"`
		Label    string          `json:"label"`
		About    string          `json:"about"`
		Count    int             `json:"count"`
		Severity map[string]int  `json:"severity"`
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
		sources = append(sources, sourceView{Key: s.Tool, Label: s.Label, About: s.About, Count: len(fs), Severity: sev, Findings: fs})
		total += len(fs)
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "sources": sources})
}
