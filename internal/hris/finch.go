package hris

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Finch reads the roster through Finch's unified employment API. Finch splits a person across three
// calls — the directory (who exists, active or not), the individual (addresses), and the employment
// (dates, type) — so a fetch is one paged listing plus two batched reads. Auth is the employer's
// access token.
type Finch struct {
	BaseURL string // empty → https://api.tryfinch.com
	Token   string
	HTTP    httpDoer
	Now     func() time.Time
}

const (
	finchPageSize  = 250
	finchBatchSize = 100
	finchVersion   = "2020-09-17"
)

type finchDirectory struct {
	Paging struct {
		Count  int `json:"count"`
		Offset int `json:"offset"`
	} `json:"paging"`
	Individuals []struct {
		ID         string `json:"id"`
		FirstName  string `json:"first_name"`
		LastName   string `json:"last_name"`
		IsActive   bool   `json:"is_active"`
		Department struct {
			Name string `json:"name"`
		} `json:"department"`
	} `json:"individuals"`
}

type finchIndividualBatch struct {
	Responses []struct {
		IndividualID string `json:"individual_id"`
		Code         int    `json:"code"`
		Body         struct {
			Emails []struct {
				Data string `json:"data"`
				Type string `json:"type"` // work | personal
			} `json:"emails"`
		} `json:"body"`
	} `json:"responses"`
}

type finchEmploymentBatch struct {
	Responses []struct {
		IndividualID string `json:"individual_id"`
		Code         int    `json:"code"`
		Body         struct {
			StartDate  string `json:"start_date"`
			EndDate    string `json:"end_date"`
			IsActive   *bool  `json:"is_active"`
			Employment struct {
				Type    string `json:"type"` // employee | contractor
				Subtype string `json:"subtype"`
			} `json:"employment"`
		} `json:"body"`
	} `json:"responses"`
}

func (f *Finch) Fetch(ctx context.Context) ([]platform.Employee, FetchReport, error) {
	rep := FetchReport{Provider: platform.HRISFinch}
	base := strings.TrimRight(f.BaseURL, "/")
	if base == "" {
		base = "https://api.tryfinch.com"
	}
	if f.Token == "" {
		return nil, rep, fmt.Errorf("finch: missing access token")
	}
	hdr := map[string]string{"Authorization": "Bearer " + f.Token, "Finch-API-Version": finchVersion}
	now := time.Now().UTC()
	if f.Now != nil {
		now = f.Now()
	}

	// 1. directory
	byID := map[string]*platform.Employee{}
	var order []string
	for offset := 0; ; offset += finchPageSize {
		var dir finchDirectory
		url := fmt.Sprintf("%s/employer/directory?limit=%d&offset=%d", base, finchPageSize, offset)
		if err := getJSON(ctx, f.HTTP, url, hdr, &dir); err != nil {
			return nil, rep, fmt.Errorf("finch: directory: %w", err)
		}
		for _, in := range dir.Individuals {
			if in.ID == "" {
				continue
			}
			status := platform.EmploymentActive
			if !in.IsActive {
				status = platform.EmploymentTerminated
			}
			e := &platform.Employee{
				Source: platform.HRISFinch, ID: in.ID,
				Name: strings.TrimSpace(in.FirstName + " " + in.LastName), Status: status,
				Department: in.Department.Name, FetchedAt: now,
			}
			byID[in.ID] = e
			order = append(order, in.ID)
		}
		if len(dir.Individuals) < finchPageSize || offset+len(dir.Individuals) >= dir.Paging.Count {
			break
		}
	}

	// 2 + 3. individual (emails) and employment (dates, type), batched
	for i := 0; i < len(order); i += finchBatchSize {
		end := i + finchBatchSize
		if end > len(order) {
			end = len(order)
		}
		ids := order[i:end]
		reqBody, _ := json.Marshal(map[string]any{"requests": idRequests(ids)})

		var ind finchIndividualBatch
		if err := doJSON(ctx, f.HTTP, "POST", base+"/employer/individual", hdr, bytes.NewReader(reqBody), &ind); err != nil {
			return nil, rep, fmt.Errorf("finch: individual: %w", err)
		}
		got := map[string]bool{}
		for _, r := range ind.Responses {
			e := byID[r.IndividualID]
			if e == nil || r.Code != 200 {
				continue
			}
			got[r.IndividualID] = true
			for _, em := range r.Body.Emails {
				switch strings.ToLower(em.Type) {
				case "work":
					if e.WorkEmail == "" {
						e.WorkEmail = em.Data
					} else {
						e.PersonalEmails = append(e.PersonalEmails, em.Data)
					}
				default:
					e.PersonalEmails = append(e.PersonalEmails, em.Data)
				}
			}
		}

		var emp finchEmploymentBatch
		if err := doJSON(ctx, f.HTTP, "POST", base+"/employer/employment", hdr, bytes.NewReader(reqBody), &emp); err != nil {
			return nil, rep, fmt.Errorf("finch: employment: %w", err)
		}
		gotEmp := map[string]bool{}
		for _, r := range emp.Responses {
			e := byID[r.IndividualID]
			if e == nil || r.Code != 200 {
				continue
			}
			gotEmp[r.IndividualID] = true
			e.StartDate, e.EndDate = datePart(r.Body.StartDate), datePart(r.Body.EndDate)
			e.EmploymentType = strings.ToLower(strings.TrimSpace(r.Body.Employment.Type))
			// The directory's is_active is authoritative for active/not; the employment record
			// refines "not active" into pending (start in the future) vs terminated.
			if e.Status == platform.EmploymentTerminated {
				if st, ok := parseDate(e.StartDate); ok && st.After(now) && e.EndDate == "" {
					e.Status = platform.EmploymentPending
				}
			}
		}
		for _, id := range ids {
			if !got[id] || !gotEmp[id] {
				rep.Unread = append(rep.Unread, firstNonEmpty(byID[id].Name, id))
			}
		}
	}

	out := make([]platform.Employee, 0, len(order))
	for _, id := range order {
		e := byID[id]
		if e.WorkEmail == "" && len(e.PersonalEmails) == 0 {
			rep.WithoutEmail++
		}
		out = append(out, *e)
	}
	rep.Employees = len(out)
	return out, rep, nil
}

func idRequests(ids []string) []map[string]string {
	out := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, map[string]string{"individual_id": id})
	}
	return out
}
