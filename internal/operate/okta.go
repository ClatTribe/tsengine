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

// Okta fetches a live identity snapshot from the Okta org's management API and assembles
// it into the operate.Workspace the posture engine consumes. OrgURL is the org base (e.g.
// https://dev-12345.okta.com); it is overridable so the fetch/parse is testable against an
// httptest server. It takes an OAuth access token per call (resolved by the platform's
// token vault) — it never holds credentials.
//
// Fetch covers the identity signals that drive the highest-value non-tech checks: users
// (status → suspended, lastLogin → stale), MFA enrollment (factors), admin roles
// (super/org admin), and OAuth grants (risky third-party integrations). Domain email-auth
// comes from DNS (operate.EmailAuth).
type Okta struct {
	OrgURL string
	HTTP   *http.Client
}

// NewOkta builds the fetcher for an org base URL.
func NewOkta(orgURL string) *Okta {
	return &Okta{OrgURL: strings.TrimRight(orgURL, "/"), HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (o *Okta) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return http.DefaultClient
}

type oktaUser struct {
	ID        string `json:"id"`
	Status    string `json:"status"` // ACTIVE | SUSPENDED | DEPROVISIONED | STAGED | ...
	LastLogin string `json:"lastLogin"`
	Profile   struct {
		Email string `json:"email"`
		Login string `json:"login"`
	} `json:"profile"`
}

// Fetch pulls the org's users (paginated) and, for each ACTIVE user, their MFA factors +
// admin roles. now is a clock injection point (stale-login math); zero Time → time.Now.
func (o *Okta) Fetch(ctx context.Context, token string, now time.Time) (Workspace, error) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	ws := Workspace{Provider: "okta"}

	grants := map[string]*oktaGrantAgg{} // clientId → aggregated grant
	next := o.OrgURL + "/api/v1/users?limit=200"
	for next != "" {
		var users []oktaUser
		link, err := o.getJSON(ctx, token, next, &users)
		if err != nil {
			return Workspace{}, err
		}
		for _, ou := range users {
			u := User{
				Email:         nz(ou.Profile.Email, ou.Profile.Login),
				Suspended:     ou.Status != "ACTIVE",
				LastLoginDays: daysSince(ou.LastLogin, now),
			}
			// Only active users get the per-user MFA/role/grant calls (and the checks that use them).
			if !u.Suspended {
				if mfa, err := o.hasActiveFactor(ctx, token, ou.ID); err == nil {
					u.MFA = mfa
				}
				if admin, super, err := o.roleLevel(ctx, token, ou.ID); err == nil {
					u.Admin, u.SuperAdmin = admin, super
				}
				o.accumulateGrants(ctx, token, ou.ID, u.Email, grants)
			}
			ws.Users = append(ws.Users, u)
		}
		next = link
	}
	ws.OAuthGrants = o.buildGrants(ctx, token, grants)
	return ws, nil
}

// oktaGrantAgg accumulates one app's grant across the users who consented to it.
type oktaGrantAgg struct {
	scopes map[string]bool
	users  map[string]bool
}

// accumulateGrants folds a user's OAuth2 grants into the per-app map. expand=scope inlines
// each grant's scope name, so AdminScope is grounded in the real consented scope. Best-
// effort: grant read needs an extra scope, and a user's failed call is simply skipped.
func (o *Okta) accumulateGrants(ctx context.Context, token, userID, email string, into map[string]*oktaGrantAgg) {
	var gs []struct {
		ClientID string `json:"clientId"`
		Embedded struct {
			Scope struct {
				Name string `json:"name"`
			} `json:"scope"`
		} `json:"_embedded"`
	}
	if _, err := o.getJSON(ctx, token, o.OrgURL+"/api/v1/users/"+userID+"/grants?expand=scope", &gs); err != nil {
		return
	}
	for _, g := range gs {
		a := into[g.ClientID]
		if a == nil {
			a = &oktaGrantAgg{scopes: map[string]bool{}, users: map[string]bool{}}
			into[g.ClientID] = a
		}
		a.users[email] = true
		if g.Embedded.Scope.Name != "" {
			a.scopes[g.Embedded.Scope.Name] = true
		}
	}
}

// buildGrants resolves app labels (best-effort) and assembles the OAuthGrants. Okta has no
// publisher-verification concept, so grants are marked Verified (the unverified-app check
// stays M365/snapshot — we don't guess); only the grounded oauth-admin-scope is emitted.
func (o *Okta) buildGrants(ctx context.Context, token string, agg map[string]*oktaGrantAgg) []OAuthGrant {
	if len(agg) == 0 {
		return nil
	}
	labels := o.appLabels(ctx, token)
	var out []OAuthGrant
	for clientID, a := range agg {
		var scopes []string
		admin := false
		for s := range a.scopes {
			scopes = append(scopes, s)
			if isOktaAdminScope(s) {
				admin = true
			}
		}
		sort.Strings(scopes)
		out = append(out, OAuthGrant{
			App: nz(labels[clientID], clientID), Scopes: scopes, Users: len(a.users),
			AdminScope: admin, Verified: true,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].App < out[j].App })
	return out
}

// appLabels maps each OAuth app's client_id to its human label (best-effort; a failure
// just yields client-id-named grants).
func (o *Okta) appLabels(ctx context.Context, token string) map[string]string {
	labels := map[string]string{}
	next := o.OrgURL + "/api/v1/apps?limit=200"
	for next != "" {
		var apps []struct {
			Label       string `json:"label"`
			Credentials struct {
				OauthClient struct {
					ClientID string `json:"client_id"`
				} `json:"oauthClient"`
			} `json:"credentials"`
		}
		link, err := o.getJSON(ctx, token, next, &apps)
		if err != nil {
			return labels
		}
		for _, ap := range apps {
			if cid := ap.Credentials.OauthClient.ClientID; cid != "" {
				labels[cid] = ap.Label
			}
		}
		next = link
	}
	return labels
}

// isOktaAdminScope reports whether an Okta API scope grants management/admin control —
// effectively shadow-admin if held by a third-party integration.
func isOktaAdminScope(scope string) bool {
	s := strings.ToLower(scope)
	return strings.Contains(s, ".manage") || strings.Contains(s, "okta.roles")
}

// hasActiveFactor reports whether the user has any enrolled (ACTIVE) MFA factor.
func (o *Okta) hasActiveFactor(ctx context.Context, token, userID string) (bool, error) {
	var factors []struct {
		FactorType string `json:"factorType"`
		Status     string `json:"status"`
	}
	if _, err := o.getJSON(ctx, token, o.OrgURL+"/api/v1/users/"+userID+"/factors", &factors); err != nil {
		return false, err
	}
	for _, f := range factors {
		if strings.EqualFold(f.Status, "ACTIVE") {
			return true, nil
		}
	}
	return false, nil
}

// roleLevel reports whether the user holds an admin role, and specifically super-admin.
func (o *Okta) roleLevel(ctx context.Context, token, userID string) (admin, super bool, err error) {
	var roles []struct {
		Type string `json:"type"`
	}
	if _, err := o.getJSON(ctx, token, o.OrgURL+"/api/v1/users/"+userID+"/roles", &roles); err != nil {
		return false, false, err
	}
	for _, r := range roles {
		if r.Type == "SUPER_ADMIN" {
			super = true
		}
		if strings.HasSuffix(r.Type, "_ADMIN") {
			admin = true
		}
	}
	return admin, super, nil
}

// getJSON GETs url with the bearer token, decodes into out, and returns the rel="next"
// pagination URL from the Link header (empty when there is no next page).
func (o *Okta) getJSON(ctx context.Context, token, url string, out any) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("okta: GET %s: HTTP %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out); err != nil {
		return "", fmt.Errorf("okta: decode %s: %w", url, err)
	}
	return nextLink(resp.Header.Values("Link")), nil
}

// nextLink extracts the URL of the rel="next" Link header (RFC 5988), or "".
func nextLink(links []string) string {
	for _, h := range links {
		for _, part := range strings.Split(h, ",") {
			if !strings.Contains(part, `rel="next"`) {
				continue
			}
			if i, j := strings.Index(part, "<"), strings.Index(part, ">"); i >= 0 && j > i {
				return part[i+1 : j]
			}
		}
	}
	return ""
}
