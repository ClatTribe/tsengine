// Package dashboard is the human-facing web UI for the autonomous security team — the
// "from UX" surface a founder / IT-generalist actually looks at (docs/autonomous-team.md
// §3.7). It is server-rendered HTML (html/template, zero JS framework, no build step),
// served by cmd/platform alongside the JSON API. One screen answers "am I okay?":
// posture by framework, open findings by severity, and the actions waiting on a human.
//
// It is read-only and tenant-scoped (the viewer's tenant id), so the dashboard can
// never approve an action — that stays the gated API path (/v1/approvals). The UI just
// shows what's pending and links to it.
package console

import (
	"context"
	"html/template"
	"net/http"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Deps are the dashboard's read collaborators.
type Deps struct {
	Store store.Store
	Token string // platform bearer token (same as the API)
}

// Handler serves the dashboard at /ui (tenant from ?tenant= or X-Tenant-ID).
func Handler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Token == "" || r.Header.Get("Authorization") != "Bearer "+d.Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tenantID := firstNonEmpty(r.URL.Query().Get("tenant"), r.Header.Get("X-Tenant-ID"))
		if tenantID == "" {
			http.Error(w, "missing tenant (?tenant=<id>)", http.StatusBadRequest)
			return
		}
		vm, err := build(r.Context(), d.Store, tenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := page.Execute(w, vm); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// view is the rendered model.
type view struct {
	TenantID    string
	Tenant      string
	RiskRating  string
	SevCounts   []sevCount
	Findings    []types.Finding
	Pending     []platform.Action
	Connections []platform.Connection
	Frameworks  []framework
}

type sevCount struct {
	Severity string
	Count    int
	Class    string
}

type framework struct {
	Name string
	Met  int
	Gap  int
}

func build(ctx context.Context, st store.Store, tenantID string) (view, error) {
	v := view{TenantID: tenantID, Tenant: tenantID}
	if t, err := st.GetTenant(ctx, tenantID); err == nil && t.Name != "" {
		v.Tenant = t.Name
	}
	findings, err := st.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return v, err
	}
	// severity tally + risk rating
	counts := map[types.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	for _, s := range []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow} {
		v.SevCounts = append(v.SevCounts, sevCount{Severity: string(s), Count: counts[s], Class: string(s)})
	}
	v.RiskRating = riskRating(counts)

	// top findings (worst first), capped for the overview
	sort.SliceStable(findings, func(i, j int) bool { return sevRank(findings[i].Severity) < sevRank(findings[j].Severity) })
	if len(findings) > 25 {
		findings = findings[:25]
	}
	v.Findings = findings

	v.Pending, _ = st.PendingApprovals(ctx, tenantID)
	conns, _ := st.ListConnections(ctx, tenantID)
	for i := range conns {
		conns[i].SecretRef = "" // never render the token ref
	}
	v.Connections = conns

	// compliance posture by framework (met vs gap)
	for _, fw := range []string{"soc2", "iso27001", "pci", "hipaa", "cis_v8", "nist_csf"} {
		cs, _ := st.Posture(ctx, tenantID, fw)
		if len(cs) == 0 {
			continue
		}
		f := framework{Name: strings.ToUpper(fw)}
		for _, c := range cs {
			if c.State == platform.ControlMet {
				f.Met++
			} else {
				f.Gap++
			}
		}
		v.Frameworks = append(v.Frameworks, f)
	}
	return v, nil
}

func riskRating(c map[types.Severity]int) string {
	switch {
	case c[types.SeverityCritical] > 0:
		return "Critical"
	case c[types.SeverityHigh] > 0:
		return "High"
	case c[types.SeverityMedium] > 0:
		return "Medium"
	case c[types.SeverityLow] > 0:
		return "Low"
	default:
		return "Clear"
	}
}

func sevRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 0
	case types.SeverityHigh:
		return 1
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 3
	}
	return 4
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

var page = template.Must(template.New("dash").Parse(pageHTML))
