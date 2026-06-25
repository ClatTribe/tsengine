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
	Users        []string `json:"users,omitempty"`
	Count        int      `json:"count"` // user count (== len(Users) when names are known)
	Scopes       []string `json:"scopes"`
	AdminConsent bool     `json:"admin_consent"` // any grant org-admin-consented → sanctioned
	Verified     bool     `json:"verified"`
	Sensitive    bool     `json:"sensitive"` // holds a high-risk scope
	ShadowIT     bool     `json:"shadow_it"` // employee-connected, no admin consent (only when known)
}

// NumUsers returns the user count whether names or a count were supplied.
func (a App) NumUsers() int {
	if len(a.Users) > 0 {
		return len(a.Users)
	}
	return a.Count
}

// sensitiveScope substrings mark a high-risk grant (data access / admin / full access across
// IdPs). Tokens are matched case-insensitively as substrings of the scope.
var sensitiveScope = []string{
	// data access (Google / M365)
	"mail", "gmail", "drive", "files", "documents", "spreadsheet", "calendar", "contacts",
	"directory", "admin", "full_access", "fullaccess", "offline_access",
	// M365 high-risk app/role/site management (User.ReadWrite.All, Sites.FullControl.All,
	// Application.ReadWrite.All — app-secret minting, RoleManagement.ReadWrite.Directory)
	"readwrite.all", "fullcontrol", "application.readwrite", "rolemanagement", "mailboxsettings",
	// GCP full-surface scopes (cloud-platform = god-mode; compute/bigquery/storage = broad)
	"cloud-platform", "compute", "bigquery", "devstorage", "iam",
	// GitHub high-risk (org admin, repo deletion, CI tampering, package/hook write)
	"repo", "read:org", "admin:org", "write:org", "delete_repo", "admin:repo_hook", "workflow", "write:packages",
	// Slack (incl. DM / private-channel history = im:history / mpim:history)
	"channels:history", "users:read", "chat:write", "groups:history", "im:history", "mpim:history", "files:read",
}

// benignScope are identity-only scopes that must NEVER count as sensitive even though they may
// substring-match a token above — e.g. the OIDC `email` scope and GitHub `user:email` both
// contain "mail". This is the FP guard (matched on the scope's last path segment too, so the
// Google URL form `.../auth/userinfo.email` is covered).
var benignScope = map[string]bool{
	"openid": true, "profile": true, "email": true, "user:email": true,
	"users:read.email": true, "userinfo.email": true, "userinfo.profile": true,
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
		a.Count = len(a.Users)
		sort.Strings(a.Users)
		sort.Strings(a.Scopes)
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// AggregatedGrant is an already-per-app grant (e.g. operate's OAuthGrant shape — providers that
// aggregate upstream, with a user COUNT not names). ConsentKnown is the honesty flag: true only
// when we actually know whether the org admin-consented; false → inventory only, NO shadow-IT
// verdict (we never label an app "shadow IT" from data that can't prove consent — FN-safe over
// a false alarm).
type AggregatedGrant struct {
	App          string
	Scopes       []string
	Users        int
	Sensitive    bool // caller already knows it holds an admin/sensitive scope (operate.AdminScope)
	Verified     bool
	AdminConsent bool
	ConsentKnown bool
}

// InventoryFromAggregated builds the inventory from already-aggregated grants (the bridge for
// operate's live cross-IdP OAuth-grant data). Shadow-IT is asserted only when consent is known.
func InventoryFromAggregated(gs []AggregatedGrant) []App {
	out := make([]App, 0, len(gs))
	for _, g := range gs {
		if strings.TrimSpace(g.App) == "" {
			continue
		}
		a := App{
			Name: g.App, Count: g.Users, Scopes: append([]string(nil), g.Scopes...),
			AdminConsent: g.AdminConsent, Verified: g.Verified, Sensitive: g.Sensitive,
		}
		for _, s := range g.Scopes {
			if isSensitive(s) {
				a.Sensitive = true
			}
		}
		a.ShadowIT = g.ConsentKnown && !g.AdminConsent
		sort.Strings(a.Scopes)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Summary is the portfolio-discovery headline (the Nudge/Wing "you have N SaaS apps" surface).
type Summary struct {
	TotalApps      int `json:"total_apps"`
	SensitiveApps  int `json:"sensitive_apps"`
	UnverifiedApps int `json:"unverified_apps"`
	ShadowITApps   int `json:"shadow_it_apps"`
	MultiUserApps  int `json:"multi_user_apps"` // adopted by ≥2 users (spreading)
}

// Summarize rolls the inventory into the portfolio summary.
func Summarize(apps []App) Summary {
	s := Summary{TotalApps: len(apps)}
	for _, a := range apps {
		if a.Sensitive {
			s.SensitiveApps++
		}
		if !a.Verified {
			s.UnverifiedApps++
		}
		if a.ShadowIT {
			s.ShadowITApps++
		}
		if a.NumUsers() >= 2 {
			s.MultiUserApps++
		}
	}
	return s
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
	return "(" + plural(a.NumUsers(), "user") + ", " + plural(len(a.Scopes), "scope") + ", " + v + ")."
}

func isSensitive(scope string) bool {
	s := strings.ToLower(strings.TrimSpace(scope))
	// Identity-only scopes are never sensitive (FP guard) — check the full scope and its last
	// path segment (Google's URL-form scopes, e.g. ".../auth/userinfo.email").
	base := s
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if benignScope[s] || benignScope[base] {
		return false
	}
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
