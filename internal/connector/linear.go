// Linear is a delivery integration (not an OAuth-onboarded scan connector): it files an
// issue for findings that have no automated fix — the SMB-favourite issue tracker, sibling
// to the Jira + ServiceNow filers. It uses a Linear personal/OAuth API key (server-to-server)
// and is configured at the platform level rather than per-tenant. Implements remediate.Filer.
package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Linear files issues into a Linear team via the GraphQL API. TeamID is the team the issue
// lands in (Linear requires it); BaseURL is overridable for tests.
type Linear struct {
	APIKey  string
	TeamID  string
	BaseURL string // default https://api.linear.app/graphql
	HTTP    *http.Client
}

// NewLinear builds the filer.
func NewLinear(apiKey, teamID string) *Linear {
	return &Linear{APIKey: apiKey, TeamID: teamID, BaseURL: "https://api.linear.app/graphql", HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func (l *Linear) client() *http.Client {
	if l.HTTP != nil {
		return l.HTTP
	}
	return http.DefaultClient
}

func (l *Linear) base() string {
	if l.BaseURL == "" {
		return "https://api.linear.app/graphql"
	}
	return strings.TrimRight(l.BaseURL, "/")
}

const linearIssueCreate = `mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success } }`

// FileTicket creates a Linear issue for the action: title = the action title; description =
// the action's summary payload (Markdown, which Linear renders natively).
func (l *Linear) FileTicket(ctx context.Context, a platform.Action) error {
	if l == nil || l.APIKey == "" || l.TeamID == "" {
		return fmt.Errorf("linear: not configured (need API key + team id)")
	}
	desc, _ := a.Payload["summary"].(string)
	body := map[string]any{
		"query": linearIssueCreate,
		"variables": map[string]any{
			"input": map[string]any{
				"teamId":      l.TeamID,
				"title":       nz(a.Title, "tsengine finding "+a.FindingID),
				"description": nz(desc, a.Title),
			},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.base(), strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	// Linear personal API keys go straight in the Authorization header (no "Bearer" prefix).
	req.Header.Set("Authorization", l.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("linear: create issue: HTTP %d: %s", resp.StatusCode, b)
	}
	// GraphQL returns 200 even on logical errors — inspect the body.
	var out struct {
		Data struct {
			IssueCreate struct {
				Success bool `json:"success"`
			} `json:"issueCreate"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return fmt.Errorf("linear: decode response: %w", err)
	}
	if len(out.Errors) > 0 {
		return fmt.Errorf("linear: create issue: %s", out.Errors[0].Message)
	}
	if !out.Data.IssueCreate.Success {
		return fmt.Errorf("linear: issueCreate returned success=false")
	}
	return nil
}
