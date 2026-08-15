package importers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- Wiz issues export (cloud posture) ---
//
// Wiz is the dominant cloud-posture tool at this company size, which makes its export the single
// most valuable list a customer can hand over. They are already paying for it, it already produces
// more findings than they can clear, and the question they have is not "what else is misconfigured"
// but "which of these can an attacker actually reach".
//
// Importing it is therefore not a competitive move — it is the wedge into a stack we are not trying
// to replace. Wiz finds the misconfiguration; we prove which ones are exploitable and chain into
// something that matters.
//
// # Shape
//
// Wiz's issue export is a JSON array, or an object with an `issues` key (the GraphQL response
// shape). Both are accepted, because a customer exporting from the console and one exporting from
// the API should not get different answers.

type wizDoc struct {
	Issues []wizIssue `json:"issues"`
}

type wizIssue struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
	Status   string `json:"status"`   // OPEN | RESOLVED | IN_PROGRESS | REJECTED
	Type     string `json:"type"`
	Note     string `json:"note"`
	Control  struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"control"`
	Entity struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"` // VIRTUAL_MACHINE | BUCKET | DATABASE | …
	} `json:"entitySnapshot"`
}

// FromWiz parses a Wiz issues export into a types.Scan.
func FromWiz(data []byte, target string, now time.Time) (types.Scan, error) {
	issues, err := parseWiz(data)
	if err != nil {
		return types.Scan{}, err
	}
	if target == "" {
		target = "wiz-cloud-account"
	}
	scan := newScan("cloud_account", target, now)
	scan.AnchorsFired = []string{"wiz"}

	n := 0
	for _, is := range issues {
		// RESOLVED and REJECTED issues are history, not the customer's current exposure. Importing
		// them would inflate the backlog we are meant to be reducing, and would put closed work back
		// in front of someone who already dealt with it.
		if st := strings.ToUpper(strings.TrimSpace(is.Status)); st == "RESOLVED" || st == "REJECTED" {
			continue
		}
		n++
		title := firstNonEmpty(is.Control.Name, is.Type, "Wiz issue")
		scan.FindingsRaw = append(scan.FindingsRaw, types.Finding{
			ID:       fmt.Sprintf("imp-wiz-%04d", n),
			RuleID:   "wiz::" + firstNonEmpty(is.Control.ID, is.Type, is.ID),
			Tool:     "wiz",
			Severity: normSeverity(is.Severity),
			Title:    title,
			// Keep Wiz's own description and the affected entity. The entity is what makes the
			// finding actionable and what lets correlation match it to something we found ourselves.
			Description:     wizDesc(is),
			Endpoint:        wizEndpoint(is),
			DiscoveredAt:    now,
			DiscoveryMethod: &types.DiscoveryMethod{Primary: "imported:wiz"},
		})
	}
	scan.FindingsEnriched = scan.FindingsRaw
	return scan, nil
}

func wizDesc(is wizIssue) string {
	parts := []string{}
	if d := strings.TrimSpace(is.Control.Description); d != "" {
		parts = append(parts, d)
	}
	if e := strings.TrimSpace(is.Entity.Name); e != "" {
		kind := strings.TrimSpace(is.Entity.Type)
		if kind == "" {
			kind = "resource"
		}
		parts = append(parts, "Affected "+strings.ToLower(kind)+": "+e)
	}
	if nte := strings.TrimSpace(is.Note); nte != "" {
		parts = append(parts, "Note: "+nte)
	}
	if len(parts) == 0 {
		return "Imported from Wiz with no description."
	}
	return strings.Join(parts, "\n\n")
}

// wizEndpoint identifies what the finding is about, preferring the resource name a human would
// recognise over an opaque id.
func wizEndpoint(is wizIssue) string {
	if n := strings.TrimSpace(is.Entity.Name); n != "" {
		return n
	}
	if i := strings.TrimSpace(is.Entity.ID); i != "" {
		return i
	}
	return "cloud-resource"
}

func parseWiz(data []byte) ([]wizIssue, error) {
	// The console exports a bare array; the API returns { "issues": [...] }. Accept both rather than
	// making a customer discover which one we wanted.
	var doc wizDoc
	if err := json.Unmarshal(data, &doc); err == nil && len(doc.Issues) > 0 {
		return doc.Issues, nil
	}
	var arr []wizIssue
	if err := json.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("wiz: %w", err)
	}
	return arr, nil
}
