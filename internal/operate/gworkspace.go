package operate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GWorkspace fetches a live identity snapshot from the Google Workspace Admin SDK
// Directory API and assembles it into the operate.Workspace the posture engine
// consumes. APIBase is overridable so the fetch/parse is testable against an httptest
// server. It takes an access token per call (resolved by the platform's token vault) —
// it never holds credentials.
//
// Fetch covers the identity signals (users: admin/MFA/stale/suspended), which drive the
// highest-value non-tech checks. Domain email-auth + OAuth grants come from the
// snapshot today (separate APIs / DNS) and are the documented next fetch.
type GWorkspace struct {
	APIBase string // default https://admin.googleapis.com
	HTTP    *http.Client
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
	return ws, nil
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
