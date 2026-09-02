package hris

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Merge reads the employee roster through Merge.dev's unified HRIS API. Merge fronts most HRIS
// products (Workday, BambooHR, Rippling, Gusto, HiBob, Personio …) behind one schema, which is why
// one fetcher here is worth fifty. Auth is the Merge account API key plus the linked-account token
// for THIS employer, sent as X-Account-Token.
type Merge struct {
	BaseURL      string // empty → https://api.merge.dev
	APIKey       string
	AccountToken string
	HTTP         httpDoer
	Now          func() time.Time
}

type mergeEmployeesPage struct {
	Next    string `json:"next"`
	Results []struct {
		ID              string          `json:"id"`
		FirstName       string          `json:"first_name"`
		LastName        string          `json:"last_name"`
		DisplayFullName string          `json:"display_full_name"`
		WorkEmail       string          `json:"work_email"`
		PersonalEmail   string          `json:"personal_email"`
		Status          string          `json:"employment_status"` // ACTIVE | PENDING | INACTIVE
		StartDate       string          `json:"start_date"`
		TerminationDate string          `json:"termination_date"`
		Employments     json.RawMessage `json:"employments"` // ids, or objects when expanded
		Groups          json.RawMessage `json:"groups"`
	} `json:"results"`
}

func (m *Merge) Fetch(ctx context.Context) ([]platform.Employee, FetchReport, error) {
	rep := FetchReport{Provider: platform.HRISMerge}
	base := strings.TrimRight(m.BaseURL, "/")
	if base == "" {
		base = "https://api.merge.dev"
	}
	if m.APIKey == "" || m.AccountToken == "" {
		return nil, rep, fmt.Errorf("merge: missing credential")
	}
	hdr := map[string]string{"Authorization": "Bearer " + m.APIKey, "X-Account-Token": m.AccountToken}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now()
	}

	q := url.Values{"page_size": {"100"}, "expand": {"employments"}}
	next := base + "/api/hris/v1/employees?" + q.Encode()
	var out []platform.Employee
	for next != "" {
		var page mergeEmployeesPage
		if err := getJSON(ctx, m.HTTP, next, hdr, &page); err != nil {
			return nil, rep, fmt.Errorf("merge: employees: %w", err)
		}
		for _, r := range page.Results {
			if r.ID == "" {
				continue
			}
			e := platform.Employee{
				Source: platform.HRISMerge, ID: r.ID,
				Name:      firstNonEmpty(r.DisplayFullName, strings.TrimSpace(r.FirstName+" "+r.LastName)),
				WorkEmail: r.WorkEmail, Status: NormalizeStatus(r.Status),
				StartDate: datePart(r.StartDate), EndDate: datePart(r.TerminationDate),
				EmploymentType: mergeEmploymentType(r.Employments), FetchedAt: now,
			}
			if p := strings.TrimSpace(r.PersonalEmail); p != "" {
				e.PersonalEmails = []string{p}
			}
			if e.WorkEmail == "" && len(e.PersonalEmails) == 0 {
				rep.WithoutEmail++
			}
			out = append(out, e)
		}
		next = page.Next
		// Merge's `next` is a cursor, not a URL.
		if next != "" && !strings.HasPrefix(next, "http") {
			q.Set("cursor", next)
			next = base + "/api/hris/v1/employees?" + q.Encode()
		}
	}
	rep.Employees = len(out)
	return out, rep, nil
}

// mergeEmploymentType reads the type off the first expanded employment. Unexpanded (id strings) or
// absent → empty, never guessed.
func mergeEmploymentType(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var objs []struct {
		Type string `json:"employment_type"`
	}
	if err := json.Unmarshal(raw, &objs); err != nil || len(objs) == 0 {
		return ""
	}
	return strings.ToLower(objs[0].Type)
}

// datePart keeps YYYY-MM-DD from an ISO datetime.
func datePart(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 10 {
		if _, err := time.Parse("2006-01-02", s[:10]); err == nil {
			return s[:10]
		}
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// --- shared HTTP (same discipline as internal/mdm: a 2xx that does not decode is an error) ---

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func doJSON(ctx context.Context, hc httpDoer, method, url string, headers map[string]string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, firstLine(b))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: response is not the expected JSON (%v): %s", url, err, firstLine(b))
	}
	return nil
}

func getJSON(ctx context.Context, hc httpDoer, url string, headers map[string]string, out any) error {
	return doJSON(ctx, hc, http.MethodGet, url, headers, nil, out)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
