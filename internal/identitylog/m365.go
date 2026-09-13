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

// M365 reads Microsoft Entra's sign-in log and directory audit through Microsoft Graph. Needs
// AuditLog.Read.All (+ Directory.Read.All for the audit half) — READ scopes.
//
// Two logs because Entra keeps them apart: signIns carries every authentication with IP, country
// and an error code (0 = success), directoryAudits carries the administrative acts — a role
// assignment, a security-info (MFA method) deletion. Both page by @odata.nextLink.
type M365 struct {
	GraphBase string // default https://graph.microsoft.com/v1.0
	HTTP      *http.Client
	PageLimit int
}

func NewM365() *M365 {
	return &M365{GraphBase: "https://graph.microsoft.com/v1.0", HTTP: netguard.GuardedClient(30 * time.Second), PageLimit: 20}
}

func (m *M365) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return netguard.GuardedClient(30 * time.Second)
}

func (m *M365) base() string {
	if m.GraphBase != "" {
		return strings.TrimRight(m.GraphBase, "/")
	}
	return "https://graph.microsoft.com/v1.0"
}

type graphSignIn struct {
	ID                string    `json:"id"`
	CreatedDateTime   time.Time `json:"createdDateTime"`
	UserPrincipalName string    `json:"userPrincipalName"`
	IPAddress         string    `json:"ipAddress"`
	Status            struct {
		ErrorCode      int    `json:"errorCode"`
		FailureReason  string `json:"failureReason"`
		AdditionalInfo string `json:"additionalDetails"`
	} `json:"status"`
	Location struct {
		Country string `json:"countryOrRegion"`
	} `json:"location"`
}

type graphAudit struct {
	ID                  string    `json:"id"`
	ActivityDateTime    time.Time `json:"activityDateTime"`
	ActivityDisplayName string    `json:"activityDisplayName"`
	Result              string    `json:"result"`
	InitiatedBy         struct {
		User struct {
			UserPrincipalName string `json:"userPrincipalName"`
			IPAddress         string `json:"ipAddress"`
		} `json:"user"`
	} `json:"initiatedBy"`
	TargetResources []struct {
		Type               string `json:"type"`
		UserPrincipalName  string `json:"userPrincipalName"`
		DisplayName        string `json:"displayName"`
		ModifiedProperties []struct {
			DisplayName string `json:"displayName"`
			NewValue    string `json:"newValue"`
		} `json:"modifiedProperties"`
	} `json:"targetResources"`
}

func (m *M365) Fetch(ctx context.Context, token string, since time.Time) (Report, error) {
	rep := Report{Provider: "m365", Since: since.UTC(), Until: time.Now().UTC(), Unmapped: map[string]int{}}
	stamp := since.UTC().Format(time.RFC3339)

	signIns := m.base() + "/auditLogs/signIns?" + url.Values{
		"$filter":  {"createdDateTime ge " + stamp},
		"$orderby": {"createdDateTime asc"},
		"$top":     {"1000"},
	}.Encode()
	if err := m.pages(ctx, token, signIns, func(raw json.RawMessage) error {
		var s graphSignIn
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		rep.Fetched++
		ev := identitythreat.Event{ID: s.ID, User: lower(s.UserPrincipalName), Time: s.CreatedDateTime.UTC(),
			IP: s.IPAddress, Country: s.Location.Country}
		if s.Status.ErrorCode == 0 {
			ev.Type = identitythreat.EventLogin
		} else {
			ev.Type = identitythreat.EventLoginFail
			ev.Detail = fmt.Sprintf("%d %s", s.Status.ErrorCode, s.Status.FailureReason)
		}
		if ev.User != "" {
			rep.Events = append(rep.Events, ev)
		}
		return nil
	}); err != nil {
		return rep, fmt.Errorf("graph signIns: %w", err)
	}

	audits := m.base() + "/auditLogs/directoryAudits?" + url.Values{
		"$filter":  {"activityDateTime ge " + stamp},
		"$orderby": {"activityDateTime asc"},
		"$top":     {"1000"},
	}.Encode()
	if err := m.pages(ctx, token, audits, func(raw json.RawMessage) error {
		var a graphAudit
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		rep.Fetched++
		if ev, ok := m365AuditEvent(a); ok {
			rep.Events = append(rep.Events, ev)
		} else {
			rep.Unmapped[a.ActivityDisplayName]++
		}
		return nil
	}); err != nil {
		return rep, fmt.Errorf("graph directoryAudits: %w", err)
	}
	// The MFA-challenge (push) rule: Graph's sign-in log records the OUTCOME of strong auth, not each
	// push sent, so MFA-fatigue by challenge count cannot be evaluated from this provider.
	rep.ChecksNotRun = map[string]string{
		"mfa_fatigue": "Entra's sign-in log records the outcome of strong authentication, not each push sent; challenge counts are not available through Graph",
	}
	return rep, nil
}

func m365AuditEvent(a graphAudit) (identitythreat.Event, bool) {
	if !strings.EqualFold(a.Result, "success") && a.Result != "" {
		return identitythreat.Event{}, false // a failed admin act changed nothing
	}
	ev := identitythreat.Event{ID: a.ID, Time: a.ActivityDateTime.UTC(), IP: a.InitiatedBy.User.IPAddress}
	target := ""
	for _, t := range a.TargetResources {
		if strings.EqualFold(t.Type, "User") && t.UserPrincipalName != "" {
			target = lower(t.UserPrincipalName)
			break
		}
	}
	name := strings.ToLower(a.ActivityDisplayName)
	switch {
	case strings.Contains(name, "add member to role") || strings.Contains(name, "add eligible member to role") ||
		strings.Contains(name, "add scoped member to role"):
		ev.Type = identitythreat.EventRoleGrant
		ev.User = target
		for _, t := range a.TargetResources {
			for _, p := range t.ModifiedProperties {
				if strings.EqualFold(p.DisplayName, "Role.DisplayName") {
					ev.Detail = strings.Trim(p.NewValue, `"`)
				}
			}
		}
		if ev.Detail == "" {
			for _, t := range a.TargetResources {
				if strings.EqualFold(t.Type, "Role") {
					ev.Detail = t.DisplayName
				}
			}
		}
		ev.Admin = isAdminRole(ev.Detail)
	case strings.Contains(name, "deleted security info") || strings.Contains(name, "delete security info"):
		ev.Type = identitythreat.EventMFARemoved
		ev.User = target
		if ev.User == "" {
			ev.User = lower(a.InitiatedBy.User.UserPrincipalName) // "User deleted security info" targets self
		}
		ev.Detail = a.ActivityDisplayName
	default:
		return ev, false
	}
	if ev.User == "" {
		return ev, false
	}
	return ev, true
}

// pages walks an @odata.nextLink chain, handing each element of `value` to fn.
func (m *M365) pages(ctx context.Context, token, next string, fn func(json.RawMessage) error) error {
	limit := m.PageLimit
	if limit <= 0 {
		limit = 20
	}
	for p := 0; next != "" && p < limit; p++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		res, err := m.client().Do(req)
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
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil || (page.Value == nil && page.NextLink == "") {
			// Not a Graph collection: an HTML sign-in page behind an expired token must not read as
			// an empty window.
			if err == nil {
				err = fmt.Errorf("response carries no value collection")
			}
			return fmt.Errorf("response is not an audit page: %w", err)
		}
		for _, raw := range page.Value {
			if err := fn(raw); err != nil {
				return err
			}
		}
		next = page.NextLink
	}
	return nil
}
