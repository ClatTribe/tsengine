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
	return ws, nil
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
