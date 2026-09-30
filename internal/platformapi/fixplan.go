package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/fixunit"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// fixplan.go: the remediation plan as something a team WORKS FROM, not something it downloads.
//
// THE GAP. The ordered plan already existed — grc.BuildRoadmap groups findings into the changes that
// close them (four CVEs in one package are one upgrade) and orders them by proof of exploitation — but
// it lived only inside the VAPT report. So the one question a team without a security engineer asks on
// Monday, "what do we do first?", was answered in a PDF, and the answer could not be acted on: the
// product opened fixes one finding at a time, per asset, while the report described the work as
// campaigns spanning every repository that carries the same vulnerable package.
//
// THREE THINGS KEEP THIS ONE PLAN RATHER THAN A SECOND ONE.
//
//  1. The ORDER and the GROUPING are grc.BuildRoadmap's, which groups on internal/fixunit — the same
//     definition the remediation engine opens bulk PRs with. The in-app plan, the report's plan and the
//     PRs the product opens all describe the same work.
//  2. The findings are the ISSUES LIST's findings: the same exclusion rules and the same in-force
//     ignore rules (IgnoreRule.Suppresses), so a risk someone accepted does not reappear as step one,
//     and one that lapsed does.
//  3. Preparing a step goes through the SAME desk every other fix goes through. Nothing here applies
//     anything (§18.2 inv. 3); it proposes, per real asset, and a human approves.
//
// What it deliberately does NOT do: estimate effort (grc.RemediationStep says why — we do not know the
// codebase or who is free) or claim a step is done. A delivered fix stays on the plan until a re-scan
// no longer finds it, because "we opened a PR" and "the vulnerability is gone" are different facts.

type fixPlanAsset struct {
	ID       string `json:"id"`
	Target   string `json:"target"`
	Type     string `json:"type"`
	Owner    string `json:"owner,omitempty"` // ADR 0028 G1 — empty means UNOWNED, never defaulted
	Findings int    `json:"findings"`
}

// fixPlanState is where the step's findings stand at the desk. Counts of FINDINGS, not actions: one
// bulk PR can close five, and "1 action" would understate how much of the step it covers.
type fixPlanState struct {
	NotProposed      int `json:"not_proposed"`      // no fix exists yet
	AwaitingApproval int `json:"awaiting_approval"` // a fix is prepared and waiting for a human
	Delivered        int `json:"delivered"`         // applied; the next scan decides whether it worked
	FixDidNotHold    int `json:"fix_did_not_hold"`  // applied AND a re-scan still found it
	Declined         int `json:"declined"`          // a human rejected the only fix proposed
}

type fixPlanStep struct {
	grc.RemediationStep
	Assets       []fixPlanAsset `json:"assets"`
	Unattributed int            `json:"unattributed"` // findings we could not tie to an asset — counted, not dropped
	State        fixPlanState   `json:"state"`
}

type fixPlanResponse struct {
	Steps        []fixPlanStep `json:"steps"`
	OpenFindings int           `json:"open_findings"`
	Ignored      int           `json:"ignored"` // findings held back by an in-force risk decision
	Note         string        `json:"note"`
}

// planFindings is the set the plan is built over: current findings, minus exclusion rules, minus the
// ones an in-force risk decision suppresses, minus coverage disclosures (they assert an absence of
// testing, not a vulnerability — there is nothing to fix).
func (d Deps) planFindings(ctx context.Context, tenantID string, now time.Time) (open []types.Finding, ignored int, err error) {
	fs, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil, 0, err
	}
	excl, err := d.Store.ListExclusionRules(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	rules, err := d.Store.ListIgnoreRules(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	suppressed := map[string]bool{}
	for _, ir := range rules {
		if ir.Suppresses(now) {
			suppressed[ir.IssueKey] = true
		}
	}
	for _, f := range crossdetect.ApplyExclusions(fs, excl) {
		if strings.HasPrefix(f.RuleID, coverageRulePrefix) {
			continue
		}
		if suppressed[crossdetect.DedupKey(f)] {
			ignored++
			continue
		}
		open = append(open, f)
	}
	return open, ignored, nil
}

// findingState maps each finding to the most advanced state any action for it has reached. Matched by
// the stable key (FindingKeys) AND by id, because finding ids are regenerated per scan and a fix
// proposed last week must still count against this week's copy of the same finding.
func findingState(acts []platform.Action, fs []types.Finding) map[string]string {
	rank := map[string]int{"declined": 1, "awaiting_approval": 2, "delivered": 3, "fix_did_not_hold": 4}
	byKey := map[string]string{}
	byID := map[string]string{}
	bump := func(m map[string]string, k, st string) {
		if rank[st] > rank[m[k]] {
			m[k] = st
		}
	}
	for _, a := range acts {
		var st string
		switch a.Status {
		case platform.ActRejected:
			st = "declined"
		case platform.ActApplied:
			st = "delivered"
		default:
			st = "awaiting_approval" // proposed, pending, approved-not-yet-applied, changes requested
		}
		for _, k := range a.FindingKeys {
			s := st
			if a.Verification != nil && hasString(a.Verification.StillPresent, k) {
				s = "fix_did_not_hold"
			}
			bump(byKey, k, s)
		}
		ids := append([]string{a.FindingID}, a.FindingIDs...)
		for _, id := range ids {
			if id != "" {
				bump(byID, id, st)
			}
		}
	}
	out := make(map[string]string, len(fs))
	for _, f := range fs {
		st := byKey[detect.Key(f)]
		if s := byID[f.ID]; rank[s] > rank[st] {
			st = s
		}
		out[f.ID] = st
	}
	return out
}

func hasString(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func (d Deps) handleFixPlan(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	now := time.Now().UTC()
	open, ignored, err := d.planFindings(ctx, tenantID, now)
	if err != nil {
		respond(w, nil, err)
		return
	}
	assets, _ := d.Store.ListAssets(ctx, tenantID)
	acts, _ := d.Store.ListActions(ctx, tenantID)
	state := findingState(acts, open)

	fixReady := map[string]bool{}
	for id, st := range state {
		if st == "awaiting_approval" {
			fixReady[id] = true
		}
	}
	byID := make(map[string]types.Finding, len(open))
	for _, f := range open {
		byID[f.ID] = f
	}
	assetByID := make(map[string]platform.Asset, len(assets))
	for _, a := range assets {
		assetByID[a.ID] = a
	}

	resp := fixPlanResponse{Steps: []fixPlanStep{}, OpenFindings: len(open), Ignored: ignored,
		Note: "Ordered by proof of exploitation, then severity. A step leaves this plan when a scan no " +
			"longer finds it — a delivered fix is not a fixed vulnerability until then. No effort " +
			"estimates: we do not know your codebase or who is free, and an invented number is the one " +
			"a sprint gets planned around."}
	for _, st := range grc.BuildRoadmap(open, fixReady) {
		step := fixPlanStep{RemediationStep: st, Assets: []fixPlanAsset{}}
		perAsset := map[string]int{}
		for _, id := range st.Findings {
			f := byID[id]
			if aid := grc.AssetForFinding(f, assets); aid != "" {
				perAsset[aid]++
			} else {
				step.Unattributed++
			}
			switch state[id] {
			case "awaiting_approval":
				step.State.AwaitingApproval++
			case "delivered":
				step.State.Delivered++
			case "fix_did_not_hold":
				step.State.FixDidNotHold++
			case "declined":
				step.State.Declined++
			default:
				step.State.NotProposed++
			}
		}
		for aid, n := range perAsset {
			a := assetByID[aid]
			step.Assets = append(step.Assets, fixPlanAsset{ID: a.ID, Target: a.Target, Type: a.Type, Owner: a.Owner, Findings: n})
		}
		sort.Slice(step.Assets, func(i, j int) bool {
			if step.Assets[i].Findings != step.Assets[j].Findings {
				return step.Assets[i].Findings > step.Assets[j].Findings
			}
			return step.Assets[i].Target < step.Assets[j].Target
		})
		resp.Steps = append(resp.Steps, step)
	}
	writeJSON(w, http.StatusOK, resp)
}

type fixPlanPrepareResponse struct {
	Key      string `json:"key"`
	Findings int    `json:"findings"`
	Assets   int    `json:"assets"`
	Queued   int    `json:"queued"`
	Pending  int    `json:"pending"`
	Applied  int    `json:"applied"`
	Detail   string `json:"detail"`
}

// handleFixPlanPrepare proposes the fixes for ONE step, across every asset it touches, through the
// desk. One step is one change repeated per asset: a package upgrade in four repositories is four
// pull requests (a PR belongs to one repository), each proposed against its REAL asset so repository
// findings become PRs rather than the generic ticket an asset-less proposal produces.
func (d Deps) handleFixPlanPrepare(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Key) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("key is required — the step's key from GET /v1/fix-plan"))
		return
	}
	if (d.ProposeFix == nil && d.ProposeBatch == nil) || d.Submitter == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("fix proposals are not configured on this deployment"))
		return
	}
	ctx := r.Context()
	open, _, err := d.planFindings(ctx, tenantID, time.Now().UTC())
	if err != nil {
		respond(w, nil, err)
		return
	}
	var step []types.Finding
	for _, f := range open {
		if fixunit.Key(f) == body.Key {
			step = append(step, f)
		}
	}
	if len(step) == 0 {
		// Not a 400: the request was fine, the work is gone — closed, suppressed or excluded since the
		// page was drawn. Saying so beats queueing an empty batch and reporting success.
		writeJSON(w, http.StatusNotFound, errBody("nothing open under this step any more — it may have been fixed, accepted or excluded since the plan was loaded"))
		return
	}
	assets, _ := d.Store.ListAssets(ctx, tenantID)
	assetByID := make(map[string]platform.Asset, len(assets))
	for _, a := range assets {
		assetByID[a.ID] = a
	}
	groups := map[string][]types.Finding{}
	var order []string
	for _, f := range step {
		aid := grc.AssetForFinding(f, assets)
		if _, ok := groups[aid]; !ok {
			order = append(order, aid)
		}
		groups[aid] = append(groups[aid], f)
	}

	before := d.countActions(ctx, tenantID)
	touched := 0
	for _, aid := range order {
		a := assetByID[aid] // zero Asset when unattributed → the proposer's generic-ticket path
		if aid != "" {
			touched++
		}
		d.proposeBatchOn(ctx, tenantID, a, groups[aid])
	}
	queued := d.countActions(ctx, tenantID) - before
	pending, applied := d.actionStateFor(ctx, tenantID, step)
	writeJSON(w, http.StatusOK, fixPlanPrepareResponse{
		Key: body.Key, Findings: len(step), Assets: touched, Queued: queued,
		Pending: pending, Applied: applied, Detail: fixDetail(queued, pending, applied),
	})
}

// proposeBatchOn proposes one asset's share of a step. With a batch proposer (remediate.ProposeBulk)
// several findings in one repository become ONE pull request; without one it falls back to the
// per-finding path. Either way it dedups on the stable key against existing actions, so preparing a
// step twice does not queue the work twice, and every action carries the keys retest needs to confirm
// the fix later.
func (d Deps) proposeBatchOn(ctx context.Context, tenantID string, asset platform.Asset, findings []types.Finding) int {
	if d.ProposeBatch == nil {
		return d.proposeForFindingsOn(ctx, tenantID, asset, findings)
	}
	asset.TenantID = tenantID
	covered := map[string]bool{}
	if existing, err := d.Store.ListActions(ctx, tenantID); err == nil {
		for _, a := range existing {
			for _, k := range a.FindingKeys {
				covered[k] = true
			}
		}
	}
	var fresh []types.Finding
	keyOf := map[string]string{}
	for _, f := range findings {
		k := detect.Key(f)
		keyOf[f.ID] = k
		if !covered[k] {
			covered[k] = true
			fresh = append(fresh, f)
		}
	}
	submitted := 0
	for _, act := range d.ProposeBatch(fresh, asset) {
		act.TenantID = tenantID
		act.FindingKeys = nil
		for _, id := range append([]string{act.FindingID}, act.FindingIDs...) {
			if k := keyOf[id]; k != "" && !hasString(act.FindingKeys, k) {
				act.FindingKeys = append(act.FindingKeys, k)
			}
		}
		if _, err := d.Submitter.Submit(ctx, act); err == nil {
			submitted++
		}
	}
	return submitted
}
