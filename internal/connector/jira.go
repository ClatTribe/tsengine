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
	if j == nil || j.BaseURL == "" || j.Project == "" {
		return fmt.Errorf("jira: not configured")
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
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.BaseURL+"/rest/api/3/issue", strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(j.Email+":"+j.APIToken)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := j.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("jira: create issue: HTTP %d", resp.StatusCode)
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
