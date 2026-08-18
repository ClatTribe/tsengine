package platformapi

import (
	"net/http"
	"sort"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// l15audit.go is the security engineer's audit surface: what the L1.5 chain SUPPRESSED or CHANGED,
// across the estate, with the rule that did it.
//
// CLAUDE.md §2.5 requires L1.5 demotions and dismissals to be "logged + recoverable so the L1
// audience can audit them", and §2.1 frames that audience as a peer rather than a subordinate. The
// engine has honoured this from the start — vulnerabilities.json carries l15_audit_log — but the
// PRODUCT never exposed it, so a security engineer using the platform could see what the AI chose to
// show them and not what it chose to hide. That is the exact affordance practitioners say they need
// before they will trust a tool's output: not "is it right", but "let me check where it was wrong".
//
// The per-rule roll-up is the actionable part. One noisy filter rule quietly suppressing forty
// findings is a decision an engineer may well disagree with, and until it is aggregated by rule it
// is invisible even to someone reading every engagement.

type l15AuditRule struct {
	Rule   string `json:"rule"`
	Action string `json:"action"`
	Count  int    `json:"count"`
}

type l15AuditView struct {
	Entries []types.AuditEntry `json:"entries"`
	Total   int                `json:"total"`
	// Dropped is the count of findings the chain DISMISSED — the ones that appear nowhere else in
	// the product, and so the only ones a reader cannot otherwise discover.
	Dropped int `json:"dropped"`
	// Demoted is the count whose severity the chain lowered; the finding is still visible, but at a
	// severity the tool did not assign it.
	Demoted int            `json:"demoted"`
	ByRule  []l15AuditRule `json:"by_rule"`
	// ScansWithAudit / ScansTotal ground an empty result. Zero entries across zero audited scans
	// means "nothing has been recorded", NOT "the AI suppressed nothing" — scans that ran before the
	// trail was captured, or with L1.5 disabled, carry none (§10).
	ScansWithAudit int    `json:"scans_with_audit"`
	ScansTotal     int    `json:"scans_total"`
	Note           string `json:"note,omitempty"`
}

// handleL15Audit returns what L1.5 changed, so a security engineer can audit and override it.
func (d Deps) handleL15Audit(w http.ResponseWriter, r *http.Request, tenantID string) {
	engs, err := d.Store.ListEngagements(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	view := l15AuditView{Entries: []types.AuditEntry{}, ByRule: []l15AuditRule{}, ScansTotal: len(engs)}
	byRule := map[l15AuditRule]int{}
	for _, e := range engs {
		if len(e.L15Audit) == 0 {
			continue
		}
		view.ScansWithAudit++
		for _, a := range e.L15Audit {
			view.Entries = append(view.Entries, a)
			switch a.Action {
			case "dismiss", "drop":
				view.Dropped++
			case "demote":
				view.Demoted++
			}
			byRule[l15AuditRule{Rule: a.Rule, Action: a.Action}]++
		}
	}
	for k, n := range byRule {
		k.Count = n
		view.ByRule = append(view.ByRule, k)
	}
	sort.Slice(view.ByRule, func(i, j int) bool {
		if view.ByRule[i].Count != view.ByRule[j].Count {
			return view.ByRule[i].Count > view.ByRule[j].Count // noisiest rule first — the one worth arguing with
		}
		return view.ByRule[i].Rule < view.ByRule[j].Rule
	})
	view.Total = len(view.Entries)

	// Ground an empty answer, rather than letting it read as "nothing was suppressed".
	if view.ScansWithAudit == 0 {
		if view.ScansTotal == 0 {
			view.Note = "No scans have run for this tenant, so nothing has been suppressed or changed yet."
		} else {
			view.Note = "None of this tenant's scans recorded an L1.5 trail — they ran before the trail was " +
				"captured, or with L1.5 disabled. This is not evidence that nothing was suppressed."
		}
	}
	respond(w, view, nil)
}
