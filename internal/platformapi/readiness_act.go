package platformapi

import (
	"context"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/ctoreadiness"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// readiness_act.go turns a checklist row from a verdict into work.
//
// A checklist that only scores is a report. What a CTO actually wants is the next click: "these four
// rows are red — close them." So a gap row hands its underlying findings to the SAME proposer the
// runner uses, and the proposals land at the SAME approval desk as everything else.
//
// Which is the point of routing it here rather than giving the agents a new power. The checklist does
// not get its own write path: it selects findings, and from there the existing gate applies —
// remediate.Propose builds the action, hitl.Desk decides whether it needs a human, and the kill-switch
// still wins over everything (§18.2 inv. 3 and 7). A row cannot cause a change that a finding could
// not have caused on its own.
//
// The two agents own different rows. The engineer owns what a scanner found and can propose a fix for;
// the pentester owns whether an attacker can actually reach it. A row owned by neither is process or
// infrastructure, and those are honestly attested rather than actioned — asking an agent to "fix"
// whether your company does code review is how a checklist starts inventing work.

type readinessFixResponse struct {
	Item     string `json:"item"`
	Agent    string `json:"agent,omitempty"`
	Findings int    `json:"findings"`
	Queued   int    `json:"queued"`
	// Pending/Applied are the real state of this practice's actions — a fix waiting for a human is a
	// different thing from one already delivered, and conflating them was the first version's bug.
	Pending int    `json:"pending"`
	Applied int    `json:"applied"`
	Detail  string `json:"detail"`
}

// handleReadinessFix proposes remediation for every finding behind one checklist row.
func (d Deps) handleReadinessFix(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")

	var item *ctoreadiness.Item
	for _, it := range ctoreadiness.Items() {
		if it.ID == id {
			c := it
			item = &c
			break
		}
	}
	if item == nil {
		writeJSON(w, http.StatusNotFound, errBody("no such practice"))
		return
	}
	// Only a measured row has findings to act on. A row we cannot observe has nothing to hand the
	// proposer, and a row we do not cover has nothing at all — saying so is more useful than queueing
	// an empty batch and reporting success.
	if item.Evidence != ctoreadiness.EvidenceObserved {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "this practice is not measured by a scanner, so there are no findings to fix. " +
				reasonFor(item.Evidence),
			"reason": "not_actionable",
		})
		return
	}

	fs, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	matched := make([]types.Finding, 0, 8)
	for _, f := range fs {
		if ctoreadiness.Matches(*item, f.Tool, f.RuleID) {
			matched = append(matched, f)
		}
	}
	if len(matched) == 0 {
		writeJSON(w, http.StatusOK, readinessFixResponse{
			Item: id, Agent: item.Agent, Detail: "Nothing open on this practice — there is no gap to close.",
		})
		return
	}

	// The same path an ingested finding takes. proposeForFindings dedups against actions that already
	// exist, so clicking twice does not queue the work twice.
	before := d.countActions(r.Context(), tenantID)
	d.proposeForFindings(r.Context(), tenantID, matched)
	queued := d.countActions(r.Context(), tenantID) - before

	// Report what is ACTUALLY true of these findings' actions, rather than assuming a zero delta
	// means "already waiting for approval".
	//
	// It usually does not. Findings are proposed the moment they are ingested, and a low-tier action
	// like filing a ticket AUTO-APPLIES rather than queueing — so the common case is that the work is
	// already done, not pending. The first version of this said "already at the approval desk" while
	// the desk was empty and all four had been delivered, which is the same overclaim this codebase
	// keeps finding elsewhere: a message asserting a state nobody checked.
	pending, applied := d.actionStateFor(r.Context(), tenantID, matched)
	writeJSON(w, http.StatusOK, readinessFixResponse{
		Item: id, Agent: item.Agent, Findings: len(matched), Queued: queued,
		Pending: pending, Applied: applied,
		Detail: fixDetail(queued, pending, applied),
	})
}

// fixDetail says what happened, in the order a person cares about: what needs them, then what is
// already done, then the honest empty case.
func fixDetail(queued, pending, applied int) string {
	switch {
	case pending > 0 && queued > 0:
		return plural(queued, "new fix", "new fixes") + " proposed. " +
			plural(pending, "fix is", "fixes are") + " waiting for your approval — nothing is applied until you say so."
	case pending > 0:
		return plural(pending, "fix is", "fixes are") + " already waiting for your approval."
	case applied > 0:
		return plural(applied, "fix has", "fixes have") + " already been delivered for this practice. " +
			"The gap stays open until the next scan confirms it closed."
	default:
		return "No fix could be proposed for these findings — they need a change we cannot make for you."
	}
}

// actionStateFor counts the tenant's actions that belong to these findings.
func (d Deps) actionStateFor(ctx context.Context, tenantID string, fs []types.Finding) (pending, applied int) {
	acts, err := d.Store.ListActions(ctx, tenantID)
	if err != nil {
		return 0, 0
	}
	ids := make(map[string]bool, len(fs))
	for _, f := range fs {
		ids[f.ID] = true
	}
	for _, a := range acts {
		hit := ids[a.FindingID]
		for _, fid := range a.FindingIDs {
			if ids[fid] {
				hit = true
			}
		}
		if !hit {
			continue
		}
		switch a.Status {
		case platform.ActPendingApproval:
			pending++
		case platform.ActApplied:
			applied++
		}
	}
	return pending, applied
}

func reasonFor(e ctoreadiness.Evidence) string {
	switch e {
	case ctoreadiness.EvidenceAttested:
		return "Confirm it instead — we record who did."
	case ctoreadiness.EvidenceCapability:
		return "Switch it on in Settings."
	case ctoreadiness.EvidenceUnbuilt:
		return "We don't cover this one."
	}
	return ""
}

func (d Deps) countActions(ctx context.Context, tenantID string) int {
	acts, err := d.Store.ListActions(ctx, tenantID)
	if err != nil {
		return 0
	}
	return len(acts)
}
