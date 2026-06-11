package operate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// M365 fetches a live identity snapshot from Microsoft Graph and assembles the
// operate.Workspace. It merges two Graph endpoints by userPrincipalName:
//   - /v1.0/users → accountEnabled (suspended) + signInActivity (stale)
//   - /v1.0/reports/authenticationMethods/userRegistrationDetails → MFA + admin
//
// APIBase is overridable for tests; it takes an access token per call and never holds
// credentials. Mirrors operate.GWorkspace.
type M365 struct {
	APIBase string // default https://graph.microsoft.com
	HTTP    *http.Client
}

// NewM365 builds the fetcher with production defaults.
func NewM365() *M365 {
	return &M365{APIBase: "https://graph.microsoft.com", HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (m *M365) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return http.DefaultClient
}

// graphUser is the slice of the Graph /users object we use.
type graphUser struct {
	UserPrincipalName string `json:"userPrincipalName"`
	AccountEnabled    bool   `json:"accountEnabled"`
	SignInActivity    struct {
		LastSignInDateTime string `json:"lastSignInDateTime"`
	} `json:"signInActivity"`
}

// regDetail is the slice of the userRegistrationDetails report we use.
type regDetail struct {
	UserPrincipalName string `json:"userPrincipalName"`
	IsMfaRegistered   bool   `json:"isMfaRegistered"`
	IsAdmin           bool   `json:"isAdmin"`
}

// Fetch pulls + merges the two reports into a Workspace. now is a clock injection point.
func (m *M365) Fetch(ctx context.Context, token string, now time.Time) (Workspace, error) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	byUPN := map[string]*User{}
	get := func(u *User, upn string) *User {
		if existing, ok := byUPN[upn]; ok {
			return existing
		}
		nu := &User{Email: upn}
		byUPN[upn] = nu
		return nu
	}

	// 1) directory users → enabled + last sign-in
	if err := m.page(ctx, token, m.base()+"/v1.0/users?$select=userPrincipalName,accountEnabled,signInActivity", func(raw json.RawMessage) error {
		var users []graphUser
		if err := json.Unmarshal(raw, &users); err != nil {
			return err
		}
		for _, gu := range users {
			u := get(nil, gu.UserPrincipalName)
			u.Suspended = !gu.AccountEnabled
			u.LastLoginDays = daysSince(gu.SignInActivity.LastSignInDateTime, now)
		}
		return nil
	}); err != nil {
		return Workspace{}, err
	}

	// 2) auth-method registration → MFA + admin
	if err := m.page(ctx, token, m.base()+"/v1.0/reports/authenticationMethods/userRegistrationDetails", func(raw json.RawMessage) error {
		var rds []regDetail
		if err := json.Unmarshal(raw, &rds); err != nil {
			return err
		}
		for _, rd := range rds {
			u := get(nil, rd.UserPrincipalName)
			u.MFA = rd.IsMfaRegistered
			u.Admin = rd.IsAdmin
		}
		return nil
	}); err != nil {
		return Workspace{}, err
	}

	ws := Workspace{Provider: "m365"}
	for _, u := range byUPN {
		ws.Users = append(ws.Users, *u)
	}
	sort.Slice(ws.Users, func(i, j int) bool { return ws.Users[i].Email < ws.Users[j].Email }) // determinism

	// 3) OAuth grants → risky third-party apps. Best-effort: grant + service-principal
	// read needs an extra Graph permission that may not be consented; if it isn't, we
	// degrade to no grants rather than failing the whole posture fetch.
	if grants, err := m.fetchGrants(ctx, token); err == nil {
		ws.OAuthGrants = grants
	}
	return ws, nil
}

// graphGrant is the slice of an oauth2PermissionGrant we use (delegated permissions).
type graphGrant struct {
	ClientID    string `json:"clientId"`    // the app's service-principal id
	ConsentType string `json:"consentType"` // AllPrincipals (admin, org-wide) | Principal (per-user)
	PrincipalID string `json:"principalId"` // the user (empty for AllPrincipals)
	Scope       string `json:"scope"`       // space-separated delegated permissions
}

// graphSP is the slice of a servicePrincipal we use (to name the app + its verified state).
type graphSP struct {
	ID                string `json:"id"`
	AppDisplayName    string `json:"appDisplayName"`
	VerifiedPublisher struct {
		DisplayName string `json:"displayName"`
	} `json:"verifiedPublisher"`
}

// fetchGrants aggregates oauth2PermissionGrants by app, resolving each app's name +
// verified-publisher state from its service principal. Fully grounded: AdminScope comes
// from the actual delegated scopes / org-wide consent, Verified from the SP's
// verifiedPublisher — both real Graph fields.
func (m *M365) fetchGrants(ctx context.Context, token string) ([]OAuthGrant, error) {
	type agg struct {
		scopes   map[string]bool
		users    map[string]bool
		adminAll bool
	}
	byClient := map[string]*agg{}
	get := func(id string) *agg {
		if a, ok := byClient[id]; ok {
			return a
		}
		a := &agg{scopes: map[string]bool{}, users: map[string]bool{}}
		byClient[id] = a
		return a
	}

	if err := m.page(ctx, token, m.base()+"/v1.0/oauth2PermissionGrants", func(raw json.RawMessage) error {
		var gs []graphGrant
		if err := json.Unmarshal(raw, &gs); err != nil {
			return err
		}
		for _, g := range gs {
			a := get(g.ClientID)
			for _, s := range strings.Fields(g.Scope) {
				a.scopes[s] = true
			}
			if strings.EqualFold(g.ConsentType, "AllPrincipals") {
				a.adminAll = true
			} else if g.PrincipalID != "" {
				a.users[g.PrincipalID] = true
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(byClient) == 0 {
		return nil, nil
	}

	// resolve names + verified state
	names, verified := map[string]string{}, map[string]bool{}
	if err := m.page(ctx, token, m.base()+"/v1.0/servicePrincipals?$select=id,appDisplayName,verifiedPublisher", func(raw json.RawMessage) error {
		var sps []graphSP
		if err := json.Unmarshal(raw, &sps); err != nil {
			return err
		}
		for _, sp := range sps {
			names[sp.ID] = sp.AppDisplayName
			verified[sp.ID] = sp.VerifiedPublisher.DisplayName != ""
		}
		return nil
	}); err != nil {
		return nil, err
	}

	var out []OAuthGrant
	for id, a := range byClient {
		users := len(a.users)
		if a.adminAll && users == 0 {
			users = 1 // org-wide consent affects ≥1 user (so unverified-app can still flag)
		}
		var scopes []string
		admin := a.adminAll && hasBroadScope(a.scopes)
		for s := range a.scopes {
			scopes = append(scopes, s)
			if isAdminScope(s) {
				admin = true
			}
		}
		sort.Strings(scopes)
		out = append(out, OAuthGrant{
			App: nz(names[id], id), Scopes: scopes, Users: users,
			AdminScope: admin, Verified: verified[id],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].App < out[j].App })
	return out, nil
}

// isAdminScope reports whether a delegated permission is directory/admin-level — i.e.
// effectively shadow-admin if granted to a third-party app.
func isAdminScope(scope string) bool {
	s := strings.ToLower(scope)
	return strings.Contains(s, "directory.") ||
		strings.Contains(s, "rolemanagement.") ||
		strings.Contains(s, ".readwrite.all") ||
		strings.Contains(s, "fullcontrol")
}

// hasBroadScope reports whether an org-wide-consented app holds any *.All scope (broad
// read/write across the tenant) — admin-grade even without a named directory scope.
func hasBroadScope(scopes map[string]bool) bool {
	for s := range scopes {
		if strings.HasSuffix(strings.ToLower(s), ".all") {
			return true
		}
	}
	return false
}

func (m *M365) base() string { return strings.TrimRight(m.APIBase, "/") }

// page follows OData @odata.nextLink, handing each page's "value" array to fn.
func (m *M365) page(ctx context.Context, token, url string, fn func(json.RawMessage) error) error {
	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := m.client().Do(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("m365: graph %s: HTTP %d", url, resp.StatusCode)
		}
		var env struct {
			Value    json.RawMessage `json:"value"`
			NextLink string          `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return fmt.Errorf("m365: decode: %w", err)
		}
		if err := fn(env.Value); err != nil {
			return err
		}
		url = env.NextLink
	}
	return nil
}
