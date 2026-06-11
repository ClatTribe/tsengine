package operate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
// (status → suspended, lastLogin → stale), MFA enrollment (factors), and admin roles
// (super/org admin). Domain email-auth comes from DNS (operate.EmailAuth); OAuth grants
// remain the documented next fetch.
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
			// Only active users get the per-user MFA/role calls (and the checks that use them).
			if !u.Suspended {
				if mfa, err := o.hasActiveFactor(ctx, token, ou.ID); err == nil {
					u.MFA = mfa
				}
				if admin, super, err := o.roleLevel(ctx, token, ou.ID); err == nil {
					u.Admin, u.SuperAdmin = admin, super
				}
			}
			ws.Users = append(ws.Users, u)
		}
		next = link
	}
	return ws, nil
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
