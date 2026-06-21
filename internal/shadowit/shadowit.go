// Package shadowit is the shadow-IT / SaaS-OAuth discovery lens (ADR 0010 Phase 6) — the SSPM
// breadth gap vs Nudge/Wing. internal/operate already fetches OAuth grants across every connected
// IdP/SaaS (Google Workspace, M365, Okta, GitHub, Slack); what was missing is the discovery lens:
// aggregate those user→app grants into a SaaS-APP INVENTORY and flag the unsanctioned
// (employee-connected, no admin consent) apps — especially the ones holding sensitive scopes.
// This is how you find the SaaS an org didn't know it had. Deterministic, grounded (§10 — a
// finding cites the real grant signals), and works across all IdPs at once (breadth for free).
package shadowit

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Grant is one user→third-party-app OAuth authorization (normalized from operate's grant fetch
// across IdPs). AdminConsent = org-level admin granted it (sanctioned); Verified = the
// publisher is verified.
type Grant struct {
	User         string   `json:"user"`
	App          string   `json:"app"`
	Scopes       []string `json:"scopes,omitempty"`
	AdminConsent bool     `json:"admin_consent,omitempty"`
	Verified     bool     `json:"verified,omitempty"`
}

// App is the aggregated inventory entry for one SaaS app across the org.
type App struct {
	Name         string   `json:"name"`
	Users        []string `json:"users"`
	Scopes       []string `json:"scopes"`
	AdminConsent bool     `json:"admin_consent"` // any grant org-admin-consented → sanctioned
	Verified     bool     `json:"verified"`
	Sensitive    bool     `json:"sensitive"` // holds a high-risk scope
	ShadowIT     bool     `json:"shadow_it"` // employee-connected, no admin consent
}

// sensitiveScope substrings mark a high-risk grant (mail/drive/admin/full access across IdPs).
var sensitiveScope = []string{
	"mail", "gmail", "drive", "files", "documents", "spreadsheet", "calendar", "contacts",
	"directory", "admin", "full_access", "fullaccess", "offline_access",
	"repo", "read:org", "channels:history", "users:read", "chat:write", "groups:history",
}

// Inventory aggregates grants into the SaaS-app inventory: one entry per app, users + scopes
// unioned, sanctioned iff any grant has admin consent. Deterministic + sorted.
func Inventory(grants []Grant) []App {
	byApp := map[string]*App{}
	userSeen := map[string]map[string]bool{}
	scopeSeen := map[string]map[string]bool{}
	for _, g := range grants {
		if strings.TrimSpace(g.App) == "" {
			continue
		}
		a := byApp[g.App]
		if a == nil {
			a = &App{Name: g.App}
			byApp[g.App] = a
			userSeen[g.App] = map[string]bool{}
			scopeSeen[g.App] = map[string]bool{}
		}
		if g.User != "" && !userSeen[g.App][g.User] {
			userSeen[g.App][g.User] = true
			a.Users = append(a.Users, g.User)
		}
		for _, s := range g.Scopes {
			if !scopeSeen[g.App][s] {
				scopeSeen[g.App][s] = true
				a.Scopes = append(a.Scopes, s)
			}
			if isSensitive(s) {
				a.Sensitive = true
			}
		}
		if g.AdminConsent {
			a.AdminConsent = true
		}
		if g.Verified {
			a.Verified = true
		}
	}
	out := make([]App, 0, len(byApp))
	for _, a := range byApp {
		a.ShadowIT = !a.AdminConsent // no org admin consent → employee-connected (shadow IT)
		sort.Strings(a.Users)
		sort.Strings(a.Scopes)
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Findings flags the risky apps in the inventory. Grounded: only fires on a real signal —
// shadow IT (no admin consent) or a sensitive scope from an unverified publisher. A sanctioned
// (admin-consented), verified, narrow-scope app produces nothing.
func Findings(apps []App) []types.Finding {
	var out []types.Finding
	for _, a := range apps {
		switch {
		case a.ShadowIT && a.Sensitive:
			out = append(out, finding(a, "shadowit::unsanctioned-sensitive", types.SeverityHigh,
				"Unsanctioned SaaS app with sensitive access: "+a.Name,
				"This third-party app was connected by employees (no org admin consent) and holds sensitive OAuth scopes — unmanaged access to company data."))
		case a.ShadowIT:
			out = append(out, finding(a, "shadowit::unsanctioned", types.SeverityMedium,
				"Unsanctioned (shadow-IT) SaaS app: "+a.Name,
				"This third-party app was connected by employees without org admin consent — discovered SaaS the org may not be governing."))
		case a.Sensitive && !a.Verified:
			out = append(out, finding(a, "shadowit::sensitive-unverified", types.SeverityMedium,
				"Sensitive-scope app from an unverified publisher: "+a.Name,
				"This admin-consented app holds sensitive scopes but its publisher is not verified."))
		}
	}
	return out
}

func finding(a App, ruleID string, sev types.Severity, title, desc string) types.Finding {
	return types.Finding{
		RuleID: ruleID, Tool: "shadowit", Severity: sev, CWE: []string{"CWE-285"},
		Endpoint: "saas-app:" + a.Name, Title: title,
		Description:     desc + " " + describe(a),
		MITRETechniques: []string{"T1098"}, // account manipulation / abused OAuth grants
	}
}

func describe(a App) string {
	v := "unverified publisher"
	if a.Verified {
		v = "verified publisher"
	}
	return "(" + plural(len(a.Users), "user") + ", " + plural(len(a.Scopes), "scope") + ", " + v + ")."
}

func isSensitive(scope string) bool {
	s := strings.ToLower(scope)
	for _, kw := range sensitiveScope {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func plural(n int, noun string) string {
	s := strconv.Itoa(n) + " " + noun
	if n != 1 {
		s += "s"
	}
	return s
}
