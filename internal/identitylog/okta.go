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

// Okta reads the System Log (GET /api/v1/logs). Needs okta.logs.read — a READ scope.
//
// The System Log is the one place every rule's signal lives for Okta: session starts carry the
// client IP and geo, MFA push sends are their own event, factor deactivation and privilege grants
// are audited. Paging is by the `Link: <…>; rel="next"` header; Okta returns a next link even on
// an empty page (the log is a stream), so the read stops on the first empty page, not on the
// absence of a link.
type Okta struct {
	OrgURL string
	HTTP   *http.Client
	// PageLimit bounds one read; a runaway spray produces tens of thousands of events and the
	// detector only needs the window.
	PageLimit int
}

func NewOkta(orgURL string) *Okta {
	return &Okta{OrgURL: strings.TrimRight(orgURL, "/"), HTTP: netguard.GuardedClient(30 * time.Second), PageLimit: 20}
}

func (o *Okta) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return netguard.GuardedClient(30 * time.Second)
}

type oktaLogEntry struct {
	UUID      string    `json:"uuid"`
	Published time.Time `json:"published"`
	EventType string    `json:"eventType"`
	Outcome   struct {
		Result string `json:"result"`
		Reason string `json:"reason"`
	} `json:"outcome"`
	Actor struct {
		AlternateID string `json:"alternateId"`
		Type        string `json:"type"`
	} `json:"actor"`
	Client struct {
		IPAddress string `json:"ipAddress"`
		Geo       struct {
			Country string `json:"country"`
		} `json:"geographicalContext"`
	} `json:"client"`
	Target []struct {
		Type        string `json:"type"`
		AlternateID string `json:"alternateId"`
		DisplayName string `json:"displayName"`
	} `json:"target"`
}

func (o *Okta) Fetch(ctx context.Context, token string, since time.Time) (Report, error) {
	rep := Report{Provider: "okta", Since: since.UTC(), Until: time.Now().UTC(), Unmapped: map[string]int{}}
	next := o.OrgURL + "/api/v1/logs?" + url.Values{
		"since":     {since.UTC().Format(time.RFC3339)},
		"limit":     {"1000"},
		"sortOrder": {"ASCENDING"},
	}.Encode()
	pages := 0
	limit := o.PageLimit
	if limit <= 0 {
		limit = 20
	}
	for next != "" && pages < limit {
		pages++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return rep, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		res, err := o.client().Do(req)
		if err != nil {
			return rep, fmt.Errorf("okta logs: %w", err)
		}
		body, rerr := io.ReadAll(io.LimitReader(res.Body, 32<<20))
		res.Body.Close()
		if rerr != nil {
			return rep, rerr
		}
		if res.StatusCode != http.StatusOK {
			return rep, fmt.Errorf("okta logs: %s: %s", res.Status, strings.TrimSpace(string(body)))
		}
		var page []oktaLogEntry
		if err := json.Unmarshal(body, &page); err != nil {
			// A 2xx that is not the log (an HTML login page from an expired token) must not read as
			// an empty window — on a detector, an empty window is "no attack".
			return rep, fmt.Errorf("okta logs: response is not a log page: %w", err)
		}
		if len(page) == 0 {
			break
		}
		for _, en := range page {
			rep.Fetched++
			if ev, ok := oktaEvent(en); ok {
				rep.Events = append(rep.Events, ev)
			} else {
				rep.Unmapped[en.EventType]++
			}
		}
		next = nextLink(res.Header.Values("Link"))
	}
	return rep, nil
}

// oktaEvent maps one System Log entry. Unmapped types return false and are counted by the caller.
func oktaEvent(en oktaLogEntry) (identitythreat.Event, bool) {
	ev := identitythreat.Event{
		ID:      en.UUID,
		User:    lower(en.Actor.AlternateID),
		Time:    en.Published.UTC(),
		IP:      en.Client.IPAddress,
		Country: en.Client.Geo.Country,
	}
	success := strings.EqualFold(en.Outcome.Result, "SUCCESS")
	switch en.EventType {
	case "user.session.start":
		if success {
			ev.Type = identitythreat.EventLogin
		} else {
			ev.Type = identitythreat.EventLoginFail
			ev.Detail = en.Outcome.Reason
		}
	case "user.authentication.auth_via_mfa":
		// A failed MFA step is a failed authentication; a successful one is already covered by the
		// session start that follows it, and counting both would double every login.
		if success {
			return ev, false
		}
		ev.Type = identitythreat.EventLoginFail
		ev.Detail = en.Outcome.Reason
	case "system.push.send_factor_verify_push":
		ev.Type = identitythreat.EventMFAChallenge
		ev.User = targetUser(en, ev.User)
	case "user.mfa.factor.deactivate", "user.mfa.factor.reset_all":
		ev.Type = identitythreat.EventMFARemoved
		ev.User = targetUser(en, ev.User)
		ev.Detail = en.EventType
	case "user.account.privilege.grant", "group.privilege.grant":
		ev.Type = identitythreat.EventRoleGrant
		ev.User = targetUser(en, ev.User)
		for _, t := range en.Target {
			if strings.EqualFold(t.Type, "Role") || strings.EqualFold(t.Type, "ROLE") {
				ev.Detail = t.DisplayName
				ev.Admin = isAdminRole(t.DisplayName)
			}
		}
		if ev.Detail == "" {
			ev.Detail = "privilege granted"
			ev.Admin = true // Okta's privilege.grant events are admin-role grants by definition
		}
	default:
		return ev, false
	}
	if ev.User == "" {
		return ev, false
	}
	return ev, true
}

// targetUser prefers the User target of an event (the account acted ON) over the actor (the
// admin who acted), because the MFA-removed and role-grant rules are about the account whose
// security changed.
func targetUser(en oktaLogEntry, fallback string) string {
	for _, t := range en.Target {
		if strings.EqualFold(t.Type, "User") && t.AlternateID != "" {
			return lower(t.AlternateID)
		}
	}
	return fallback
}

// nextLink extracts the rel="next" URL from Link headers.
func nextLink(links []string) string {
	for _, l := range links {
		for _, part := range strings.Split(l, ",") {
			if !strings.Contains(part, `rel="next"`) {
				continue
			}
			start, end := strings.Index(part, "<"), strings.Index(part, ">")
			if start >= 0 && end > start {
				return part[start+1 : end]
			}
		}
	}
	return ""
}
