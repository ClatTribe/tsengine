package platformapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
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
	// Suppressed are the dropped findings themselves, so the engineer can judge the AI's call on the
	// evidence rather than on a rule name — and reinstate one it got wrong.
	Suppressed []types.Finding `json:"suppressed"`
	Total      int             `json:"total"`
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
	view := l15AuditView{Entries: []types.AuditEntry{}, Suppressed: []types.Finding{}, ByRule: []l15AuditRule{}, ScansTotal: len(engs)}
	byRule := map[l15AuditRule]int{}
	for _, e := range engs {
		if len(e.L15Audit) == 0 {
			continue
		}
		view.ScansWithAudit++
		view.Suppressed = append(view.Suppressed, e.L15Dismissed...)
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

// reinstateRequest names the suppressed finding a human wants back.
type reinstateRequest struct {
	FindingID string `json:"finding_id"`
	Reason    string `json:"reason,omitempty"`
	By        string `json:"by,omitempty"`
}

// handleL15Reinstate puts a finding the chain dismissed BACK into the tenant's findings — the
// override half of §2.5 ("the audit log ... exposed to the security engineer for override").
//
// Visibility without override is half an affordance: telling an engineer "we dropped 40 findings by
// rule X" while giving them no way to disagree leaves the AI's judgement final, which is exactly the
// posture practitioners reject. The reinstated finding is marked as a HUMAN decision rather than
// silently rejoining the queue as though the AI had approved it — the provenance of a finding is
// part of its evidence (§10).
func (d Deps) handleL15Reinstate(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req reinstateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if strings.TrimSpace(req.FindingID) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("finding_id is required"))
		return
	}
	engs, err := d.Store.ListEngagements(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	// Tenant-scoped by construction: only this tenant's engagements are searched (§18.2 inv. 2).
	var found *types.Finding
	for _, e := range engs {
		for i := range e.L15Dismissed {
			if e.L15Dismissed[i].ID == req.FindingID {
				f := e.L15Dismissed[i]
				found = &f
				break
			}
		}
		if found != nil {
			break
		}
	}
	if found == nil {
		writeJSON(w, http.StatusNotFound, errBody("no suppressed finding with that id for this tenant"))
		return
	}

	// Mark the provenance. A reinstated finding is one a human vouched for over the filter's
	// objection, and a reader deserves to know that rather than seeing an ordinary finding.
	if found.DiscoveryMethod == nil {
		found.DiscoveryMethod = &types.DiscoveryMethod{}
	}
	found.DiscoveryMethod.Primary = platform.DiscoveryHumanReinstated
	who := strings.TrimSpace(req.By)
	if who == "" {
		who = "security engineer"
	}
	note := "Reinstated by " + who + " over the L1.5 filter's dismissal."
	if rs := strings.TrimSpace(req.Reason); rs != "" {
		note += " Reason: " + rs
	}
	found.Description = strings.TrimSpace(found.Description + "\n\n" + note)

	if err := d.Store.PutFinding(r.Context(), tenantID, *found); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("l1.5 dismissal overridden", "l15_reinstate",
			map[string]any{"tenant_id": tenantID, "finding_id": req.FindingID, "by": who, "reason": req.Reason},
			"a security engineer reinstated a finding the FP filter dropped (§2.5 override)")
	}
	writeJSON(w, http.StatusOK, map[string]any{"reinstated": found.ID, "rule_id": found.RuleID, "by": who})
}
