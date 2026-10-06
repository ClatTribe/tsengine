// Jira is a delivery integration (not an OAuth-onboarded scan connector): it files a
// ticket for findings that have no automated fix — the default path for non-tech
// posture findings (MFA gaps, DMARC) and anything else the agent can't auto-remediate.
// It uses Jira Cloud basic auth (email + API token), which is the pragmatic choice for
// a server-to-server filer, and is configured at the platform level rather than
// per-tenant OAuth. Implements remediate.Filer.
package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/netguard"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Jira files issues into a Jira Cloud project. BaseURL is the site
// (https://acme.atlassian.net); Project is the key (e.g. "SEC").
type Jira struct {
	BaseURL   string
	Email     string
	APIToken  string
	Project   string
	IssueType string // default "Task"
	HTTP      *http.Client
}

// NewJira builds the filer. BaseURL is tenant-configurable (Tenant.Jira), so the production client uses
// an SSRF-guarded transport that refuses any non-public host (loopback / RFC1918 / cloud metadata) at
// dial time — closing the rebind window between when a tenant saves the URL and when a ticket is filed.
func NewJira(baseURL, email, apiToken, project string) *Jira {
	return &Jira{
		BaseURL: strings.TrimRight(baseURL, "/"), Email: email, APIToken: apiToken,
		Project: project, IssueType: "Task", HTTP: netguard.GuardedClient(20 * time.Second),
	}
}

func (j *Jira) client() *http.Client {
	if j.HTTP != nil {
		return j.HTTP
	}
	return http.DefaultClient
}

// FileTicket creates a Jira issue for the action. summary = the action title;
// description = the action's summary payload (rendered as Atlassian Document Format).
func (j *Jira) FileTicket(ctx context.Context, a platform.Action) error {
	_, err := j.FileTicketRef(ctx, a)
	return err
}

// FileTicketRef creates the issue and returns its key. The key used to be discarded, which is why
// nothing could ever learn whether the ticket was closed (internal/ticketsync).
func (j *Jira) FileTicketRef(ctx context.Context, a platform.Action) (platform.TicketRef, error) {
	if j == nil || j.BaseURL == "" || j.Project == "" {
		return platform.TicketRef{}, fmt.Errorf("jira: not configured")
	}
	desc, _ := a.Payload["summary"].(string)
	issueType := j.IssueType
	if issueType == "" {
		issueType = "Task"
	}
	body := map[string]any{
		"fields": map[string]any{
			"project":     map[string]any{"key": j.Project},
			"summary":     nz(a.Title, "tsengine finding "+a.FindingID),
			"issuetype":   map[string]any{"name": issueType},
			"description": adf(nz(desc, a.Title)),
		},
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := j.do(ctx, http.MethodPost, "/rest/api/3/issue", body, &created); err != nil {
		return platform.TicketRef{}, fmt.Errorf("jira: create issue: %w", err)
	}
	ref := platform.TicketRef{System: "jira", Key: created.Key}
	if created.Key != "" {
		ref.URL = j.BaseURL + "/browse/" + created.Key
	}
	return ref, nil
}

// IssueStatus is what Jira says about one issue now.
type IssueStatus struct {
	Name       string    // the workflow's own status name ("Won't Do", "Released")
	Category   string    // Jira's FIXED category key: new | indeterminate | done
	Resolution string    // e.g. "Done", "Won't Do"; empty while unresolved
	ResolvedAt time.Time // zero while unresolved
}

// TicketStatus reads an issue's status. The CATEGORY is what callers should branch on: status names
// are per-workflow and arbitrary ("Shipped", "QA passed"), while statusCategory.key is one of three
// fixed values on every Jira site — matching on names would work for one customer and silently never
// fire for the next.
func (j *Jira) TicketStatus(ctx context.Context, key string) (IssueStatus, error) {
	if j == nil || j.BaseURL == "" {
		return IssueStatus{}, fmt.Errorf("jira: not configured")
	}
	var out struct {
		Fields struct {
			Status struct {
				Name           string `json:"name"`
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
			Resolution *struct {
				Name string `json:"name"`
			} `json:"resolution"`
			ResolutionDate string `json:"resolutiondate"`
		} `json:"fields"`
	}
	if err := j.do(ctx, http.MethodGet, "/rest/api/3/issue/"+url.PathEscape(key)+"?fields=status,resolution,resolutiondate", nil, &out); err != nil {
		return IssueStatus{}, fmt.Errorf("jira: read %s: %w", key, err)
	}
	st := IssueStatus{Name: out.Fields.Status.Name, Category: out.Fields.Status.StatusCategory.Key}
	if out.Fields.Resolution != nil {
		st.Resolution = out.Fields.Resolution.Name
	}
	if out.Fields.ResolutionDate != "" {
		// Jira's own format ("2026-10-05T10:11:12.000+0000"), not RFC 3339.
		if t, err := time.Parse("2006-01-02T15:04:05.000-0700", out.Fields.ResolutionDate); err == nil {
			st.ResolvedAt = t.UTC()
		}
	}
	return st, nil
}

// AddComment posts a plain-text comment on an issue — the write half of the two-way sync. A comment,
// never a transition: reopening someone's ticket needs workflow-specific transition ids and is a
// decision about THEIR process; saying what our re-test found is information they can act on.
func (j *Jira) AddComment(ctx context.Context, key, text string) error {
	if j == nil || j.BaseURL == "" {
		return fmt.Errorf("jira: not configured")
	}
	if err := j.do(ctx, http.MethodPost, "/rest/api/3/issue/"+url.PathEscape(key)+"/comment",
		map[string]any{"body": adf(text)}, nil); err != nil {
		return fmt.Errorf("jira: comment on %s: %w", key, err)
	}
	return nil
}

// do issues one authenticated request; out (optional) receives the JSON body.
func (j *Jira) do(ctx context.Context, method, path string, in, out any) error {
	var rdr io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rdr = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, j.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(j.Email+":"+j.APIToken)))
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
	}
	return nil
}

// adf wraps plain text in a minimal Atlassian Document Format doc (Jira Cloud v3 needs
// rich-text descriptions, not a bare string).
func adf(text string) map[string]any {
	return map[string]any{
		"type": "doc", "version": 1,
		"content": []any{
			map[string]any{
				"type":    "paragraph",
				"content": []any{map[string]any{"type": "text", "text": text}},
			},
		},
	}
}
