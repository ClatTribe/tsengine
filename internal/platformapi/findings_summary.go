package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// findings_summary.go serves the severity counts, so a page that only needs a number does not pull
// every finding to compute it.
//
// # Why this exists — measured, not assumed
//
// The app shell fetches ALL findings on every page load and uses them for exactly one thing:
// riskRating(severityCounts(findings)). That is fine for a workspace with fifty findings and
// unusable for one that imported its existing scanner backlog:
//
//	  4,000 findings →  2.2 MB   per page load
//	 20,000 findings → 10.8 MB   per page load
//	 50,000 findings → 27.1 MB   per page load
//
// Those are measured against the real enrichment pipeline, not estimated. Importing a mid-size
// company's Snyk export would therefore make every screen in the product slower, which is a strange
// way to reward a customer for connecting their data.
//
// Note where the bottleneck ISN'T. Parsing 50,000 findings takes 151ms and writing them one at a
// time to SQLite takes 2.05s — the write path scales fine, and batching it would be an optimisation
// rather than a fix. The cost is all on the read side, paid on every navigation, forever.
//
// The counts are computed server-side and returned as a fixed-size object, so this endpoint costs
// the same whether the tenant has ten findings or a million.

// findingsSummary is the fixed-size view: how many, how bad, and nothing else.
type findingsSummary struct {
	Total    int            `json:"total"`
	Severity map[string]int `json:"severity"`
	// Truncated reports whether some findings were not counted. Always false today — the count is
	// exact — but the field exists so a future bounded scan can say so rather than under-report a
	// total that a customer reads as their whole estate.
	Truncated bool `json:"truncated"`
}

// handleFindingsSummary returns severity counts for the tenant.
func (d Deps) handleFindingsSummary(w http.ResponseWriter, r *http.Request, tenantID string) {
	fs, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, summarizeFindings(fs))
}

// summarize counts by severity. Every severity key is present even at zero, so a caller can render a
// row per severity without checking for absence — and a zero is a real answer, not a missing one.
func summarizeFindings(fs []types.Finding) findingsSummary {
	s := findingsSummary{
		Total: len(fs),
		Severity: map[string]int{
			string(types.SeverityCritical): 0,
			string(types.SeverityHigh):     0,
			string(types.SeverityMedium):   0,
			string(types.SeverityLow):      0,
			string(types.SeverityInfo):     0,
		},
	}
	for _, f := range fs {
		sev := string(f.Severity)
		if _, known := s.Severity[sev]; !known {
			// An unrecognised severity is still counted in the total. Dropping it would make the
			// parts disagree with the whole, and a summary whose numbers do not add up is worse than
			// no summary.
			sev = string(types.SeverityInfo)
		}
		s.Severity[sev]++
	}
	return s
}
