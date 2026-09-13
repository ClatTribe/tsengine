package identitylog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/identitythreat"
	"github.com/ClatTribe/tsengine/internal/netguard"
)

// GWorkspace reads the Admin SDK Reports API — the `login` application for sign-ins and challenges,
// the `admin` application for role grants and 2-Step-Verification changes. Needs
// admin.reports.audit.readonly — a READ scope.
//
// Google's login events carry an IP but NO country, so impossible-travel cannot be evaluated from
// this provider; the report declares it rather than letting the rule read as clean.
type GWorkspace struct {
	APIBase   string // default https://admin.googleapis.com
	HTTP      *http.Client
	PageLimit int
}

func NewGWorkspace() *GWorkspace {
	return &GWorkspace{APIBase: "https://admin.googleapis.com", HTTP: netguard.GuardedClient(30 * time.Second), PageLimit: 20}
}

func (g *GWorkspace) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return netguard.GuardedClient(30 * time.Second)
}

func (g *GWorkspace) base() string {
	if g.APIBase != "" {
		return strings.TrimRight(g.APIBase, "/")
	}
	return "https://admin.googleapis.com"
}

type gwsActivity struct {
	ID struct {
		Time            time.Time `json:"time"`
		UniqueQualifier string    `json:"uniqueQualifier"`
		ApplicationName string    `json:"applicationName"`
	} `json:"id"`
	Actor struct {
		Email string `json:"email"`
	} `json:"actor"`
	IPAddress string `json:"ipAddress"`
	Events    []struct {
		Name       string `json:"name"`
		Parameters []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"parameters"`
	} `json:"events"`
}

func (g *GWorkspace) Fetch(ctx context.Context, token string, since time.Time) (Report, error) {
	rep := Report{Provider: "gworkspace", Since: since.UTC(), Until: time.Now().UTC(), Unmapped: map[string]int{}}
	for _, app := range []string{"login", "admin"} {
		u := g.base() + "/admin/reports/v1/activity/users/all/applications/" + app + "?" + url.Values{
			"startTime":  {since.UTC().Format(time.RFC3339)},
			"maxResults": {"1000"},
		}.Encode()
		if err := g.pages(ctx, token, u, func(a gwsActivity) {
			for i, e := range a.Events {
				rep.Fetched++
				if ev, ok := gwsEvent(app, a, i); ok {
					rep.Events = append(rep.Events, ev)
				} else {
					rep.Unmapped[app+":"+e.Name]++
				}
			}
		}); err != nil {
			return rep, fmt.Errorf("google reports %s: %w", app, err)
		}
	}
	rep.ChecksNotRun = map[string]string{
		"impossible_travel": "Google's login events carry an IP address but no country, so two-country travel cannot be evaluated from the Reports API",
	}
	return rep, nil
}

func gwsEvent(app string, a gwsActivity, i int) (identitythreat.Event, bool) {
	e := a.Events[i]
	param := func(name string) string {
		for _, p := range e.Parameters {
			if strings.EqualFold(p.Name, name) {
				return p.Value
			}
		}
		return ""
	}
	ev := identitythreat.Event{
		ID:   a.ID.UniqueQualifier + ":" + fmt.Sprint(i),
		User: lower(a.Actor.Email),
		Time: a.ID.Time.UTC(),
		IP:   a.IPAddress,
	}
	switch app + ":" + e.Name {
	case "login:login_success":
		ev.Type = identitythreat.EventLogin
	case "login:login_failure":
		ev.Type = identitythreat.EventLoginFail
		ev.Detail = param("login_failure_type")
	case "login:login_challenge":
		ev.Type = identitythreat.EventMFAChallenge
		ev.Detail = param("login_challenge_method")
	case "admin:ASSIGN_ROLE":
		ev.Type = identitythreat.EventRoleGrant
		if u := param("USER_EMAIL"); u != "" {
			ev.User = lower(u)
		}
		ev.Detail = param("ROLE_NAME")
		ev.Admin = isAdminRole(ev.Detail)
	case "admin:UNENROLL_USER_FROM_STRONG_AUTH", "admin:REVOKE_2SV", "admin:2SV_DISABLE":
		ev.Type = identitythreat.EventMFARemoved
		if u := param("USER_EMAIL"); u != "" {
			ev.User = lower(u)
		}
		ev.Detail = e.Name
	default:
		return ev, false
	}
	if ev.User == "" {
		return ev, false
	}
	return ev, true
}

func (g *GWorkspace) pages(ctx context.Context, token, first string, fn func(gwsActivity)) error {
	limit := g.PageLimit
	if limit <= 0 {
		limit = 20
	}
	next := first
	for p := 0; next != "" && p < limit; p++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		res, err := g.client().Do(req)
		if err != nil {
			return err
		}
		body, rerr := io.ReadAll(io.LimitReader(res.Body, 32<<20))
		res.Body.Close()
		if rerr != nil {
			return rerr
		}
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %s", res.Status, strings.TrimSpace(string(body)))
		}
		var page struct {
			Kind          string        `json:"kind"`
			Items         []gwsActivity `json:"items"`
			NextPageToken string        `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &page); err != nil || page.Kind == "" {
			if err == nil {
				err = fmt.Errorf("response carries no kind")
			}
			return fmt.Errorf("response is not a Reports page: %w", err)
		}
		for _, a := range page.Items {
			fn(a)
		}
		if page.NextPageToken == "" {
			break
		}
		nu, perr := url.Parse(first)
		if perr != nil {
			return perr
		}
		q := nu.Query()
		q.Set("pageToken", page.NextPageToken)
		nu.RawQuery = q.Encode()
		next = nu.String()
	}
	return nil
}
