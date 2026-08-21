package operate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// GWorkspace fetches a live identity snapshot from the Google Workspace Admin SDK
// Directory API and assembles it into the operate.Workspace the posture engine
// consumes. APIBase is overridable so the fetch/parse is testable against an httptest
// server. It takes an access token per call (resolved by the platform's token vault) —
// it never holds credentials.
//
// Fetch covers users (admin/MFA/stale/suspended) and now their OAuth grants (risky
// third-party apps, via the Directory users.tokens API). Domain email-auth is resolved
// live separately (operate.EmailAuth, via DNS).
type GWorkspace struct {
	APIBase string // default https://admin.googleapis.com
	HTTP    *http.Client

	// grantReadFailures counts per-user token lookups that failed during the current
	// fetch. fetchGrants swallows them individually on purpose — one user's failure must
	// not lose everyone else's apps — but that makes a TOTAL failure indistinguishable
	// from a workspace with no third-party apps. The counter is what tells them apart.
	grantReadFailures int
}

// NewGWorkspace builds the connector with production defaults.
func NewGWorkspace() *GWorkspace {
	return &GWorkspace{APIBase: "https://admin.googleapis.com", HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (g *GWorkspace) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return http.DefaultClient
}

// directoryUser is the slice of the Admin SDK user object we use.
type directoryUser struct {
	PrimaryEmail     string `json:"primaryEmail"`
	IsAdmin          bool   `json:"isAdmin"`          // super-admin
	IsDelegatedAdmin bool   `json:"isDelegatedAdmin"` // delegated admin
	Suspended        bool   `json:"suspended"`
	IsEnrolledIn2Sv  bool   `json:"isEnrolledIn2Sv"` // MFA
	LastLoginTime    string `json:"lastLoginTime"`   // RFC3339; epoch-zero string = never
}

type usersResp struct {
	Users         []directoryUser `json:"users"`
	NextPageToken string          `json:"nextPageToken"`
}

// Fetch pulls the directory and assembles a Workspace. now is a clock injection point
// (stale-login math); pass the zero Time for time.Now.
func (g *GWorkspace) Fetch(ctx context.Context, token string, now time.Time) (Workspace, error) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	ws := Workspace{Provider: "gworkspace"}

	page := ""
	for {
		ur, err := g.fetchPage(ctx, token, page)
		if err != nil {
			return Workspace{}, err
		}
		for _, du := range ur.Users {
			ws.Users = append(ws.Users, mapUser(du, now))
		}
		if ur.NextPageToken == "" {
			break
		}
		page = ur.NextPageToken
	}

	// OAuth grants → risky third-party apps. Best-effort + per-user (users.tokens needs an
	// extra scope; a single user's failure never drops the rest). Skip suspended accounts.
	emails := make([]string, 0, len(ws.Users))
	for _, u := range ws.Users {
		if !u.Suspended {
			emails = append(emails, u.Email)
		}
	}
	grants, grantsOK := g.fetchGrantsChecked(ctx, token, emails)
	ws.OAuthGrants = grants
	if !grantsOK {
		// The read failed or was never permitted. Without this the scan reports a clean
		// OAuth posture for a workspace whose apps it never saw.
		ws.Unavailable = append(ws.Unavailable, "oauth_grants")
	}
	// Google's tokens API exposes scopes but NOT publisher verification, so the
	// unverified-app check cannot run here at all — a provider limit, not a missing scope.
	// Declared whenever we did read grants, since that is when a customer would otherwise
	// assume the app review was complete.
	if grantsOK {
		ws.ProviderLimits = append(ws.ProviderLimits, "oauth_publisher_verification")
	}
	return ws, nil
}

// gwsToken is the slice of a Directory API users.tokens item we use.
type gwsToken struct {
	ClientID    string   `json:"clientId"`
	DisplayText string   `json:"displayText"`
	Scopes      []string `json:"scopes"`
}

// fetchGrants aggregates each user's third-party OAuth tokens into per-app grants. Google's
// tokens API exposes the granted scopes (→ AdminScope, grounded) but NOT publisher
// verification, so grants are marked Verified=true — the unverified-app check stays
// M365/snapshot-only rather than us guessing. Best-effort: any user's failed call (or a
// missing scope) is skipped, never fatal.
// fetchGrantsChecked wraps fetchGrants and reports whether the read actually succeeded.
//
// fetchGrants swallows per-user errors by design (one user's failure should not lose the
// rest), which means a total failure and a genuinely app-free workspace both return an
// empty slice. ok=false when EVERY user lookup failed — that is the case where the empty
// result carries no information and must not be read as a clean posture.
func (g *GWorkspace) fetchGrantsChecked(ctx context.Context, token string, emails []string) ([]OAuthGrant, bool) {
	if len(emails) == 0 {
		return nil, true // nobody to ask about; not a failed read
	}
	before := g.grantReadFailures
	out := g.fetchGrants(ctx, token, emails)
	return out, g.grantReadFailures-before < len(emails)
}

func (g *GWorkspace) fetchGrants(ctx context.Context, token string, emails []string) []OAuthGrant {
	type agg struct {
		name   string
		scopes map[string]bool
		users  map[string]bool
	}
	byApp := map[string]*agg{}
	for _, email := range emails {
		var tr struct {
			Items []gwsToken `json:"items"`
		}
		u := strings.TrimRight(g.APIBase, "/") + "/admin/directory/v1/users/" + url.PathEscape(email) + "/tokens"
		if err := g.getJSON(ctx, token, u, &tr); err != nil {
			g.grantReadFailures++
			continue
		}
		for _, t := range tr.Items {
			key := nz(t.ClientID, t.DisplayText)
			a := byApp[key]
			if a == nil {
				a = &agg{name: nz(t.DisplayText, t.ClientID), scopes: map[string]bool{}, users: map[string]bool{}}
				byApp[key] = a
			}
			a.users[email] = true
			for _, s := range t.Scopes {
				a.scopes[s] = true
			}
		}
	}
	var out []OAuthGrant
	for _, a := range byApp {
		var scopes []string
		admin := false
		for s := range a.scopes {
			scopes = append(scopes, s)
			if isGoogleAdminScope(s) {
				admin = true
			}
		}
		sort.Strings(scopes)
		out = append(out, OAuthGrant{App: a.name, Scopes: scopes, Users: len(a.users), AdminScope: admin, Verified: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].App < out[j].App })
	return out
}

// isGoogleAdminScope reports whether a Google OAuth scope grants directory/admin control —
// effectively shadow-admin if held by a third-party app.
func isGoogleAdminScope(scope string) bool {
	s := strings.ToLower(scope)
	return strings.Contains(s, "/auth/admin.") || strings.Contains(s, "/auth/cloud-platform")
}

// getJSON GETs url with the bearer token and decodes the body into out.
func (g *GWorkspace) getJSON(ctx context.Context, token, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gworkspace: GET %s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

func (g *GWorkspace) fetchPage(ctx context.Context, token, page string) (usersResp, error) {
	q := url.Values{"customer": {"my_customer"}, "maxResults": {"500"}, "projection": {"full"}}
	if page != "" {
		q.Set("pageToken", page)
	}
	u := strings.TrimRight(g.APIBase, "/") + "/admin/directory/v1/users?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return usersResp{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := g.client().Do(req)
	if err != nil {
		return usersResp{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return usersResp{}, fmt.Errorf("gworkspace: list users: HTTP %d", resp.StatusCode)
	}
	var ur usersResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&ur); err != nil {
		return usersResp{}, fmt.Errorf("gworkspace: decode users: %w", err)
	}
	return ur, nil
}

// mapUser converts an Admin SDK user to an operate.User, computing days-since-login.
func mapUser(du directoryUser, now time.Time) User {
	return User{
		Email:         du.PrimaryEmail,
		SuperAdmin:    du.IsAdmin,
		Admin:         du.IsDelegatedAdmin,
		MFA:           du.IsEnrolledIn2Sv,
		Suspended:     du.Suspended,
		LastLoginDays: daysSince(du.LastLoginTime, now),
	}
}

// daysSince parses an RFC3339 login time and returns whole days since it. A never-logged-in
// account (epoch-zero or unparseable) is treated as maximally stale.
func daysSince(ts string, now time.Time) int {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil || t.Year() <= 1970 {
		return 99999 // never logged in → maximally stale
	}
	d := int(now.Sub(t).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}
