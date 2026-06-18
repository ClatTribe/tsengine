// ServiceNow is a delivery integration (not an OAuth-onboarded scan connector): it files an
// incident for findings with no automated fix — the ITSM equivalent of the Jira filer, for
// shops standardized on ServiceNow. Platform-level Basic auth (a service account), the
// pragmatic server-to-server choice. Implements remediate.Filer.
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

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ServiceNow files incidents into a ServiceNow instance via the Table API. InstanceURL is
// the site (https://acme.service-now.com).
type ServiceNow struct {
	InstanceURL string
	User        string
	Password    string
	HTTP        *http.Client
}

// NewServiceNow builds the filer.
func NewServiceNow(instanceURL, user, password string) *ServiceNow {
	return &ServiceNow{
		InstanceURL: strings.TrimRight(instanceURL, "/"), User: user, Password: password,
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

func (s *ServiceNow) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return http.DefaultClient
}

// FileTicket creates a ServiceNow incident (Table API) for the action: short_description =
// the action title, description = the remediation summary, tagged to the security category.
func (s *ServiceNow) FileTicket(ctx context.Context, a platform.Action) error {
	if s == nil || s.InstanceURL == "" {
		return fmt.Errorf("servicenow: not configured")
	}
	desc, _ := a.Payload["summary"].(string)
	body := map[string]any{
		"short_description": nz(a.Title, "tsengine finding "+a.FindingID),
		"description":       nz(desc, a.Title),
		"category":          "security",
		"urgency":           "2",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.InstanceURL+"/api/now/table/incident", strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.User+":"+s.Password)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("servicenow: create incident: HTTP %d", resp.StatusCode)
	}
	return nil
}
