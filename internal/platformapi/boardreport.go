package platformapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/coverage"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/exposuretrend"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// boardreport.go: the one page a CTO takes to a board or an investor update.
//
// Every section is a number the product ALREADY computes elsewhere — the issues list's findings, the
// fix plan's order, the exposure trend and its graded objective, the risk decisions, the coverage roll-up
// — assembled, never re-derived, so the page cannot disagree with the screens it summarises. What makes it
// a report a board can rely on is what it REFUSES to do:
//
//   - No single score. A blended "security score" rises as a customer connects less (fewer findings
//     visible), which is the number a board most wants and the one this product will not print.
//   - Every figure travels with the fact that bounds it: exposure "closed" beside "proven closed",
//     assets scanned beside assets never scanned, accepted risks beside lapsed ones. A board reads the
//     headline and nothing else, so the headline itself carries the caveats.
//   - "Not graded" is its own state. Too little history is not a missed objective.

type boardExposure struct {
	Objective      exposuretrend.Verdict `json:"objective"`
	Opened30       int                   `json:"opened_30d"`
	Closed30       int                   `json:"closed_30d"`
	ConfirmedFixed int                   `json:"confirmed_fixed"`
	Caveat         string                `json:"caveat"`
}

type boardProven struct {
	OpenIssues     int            `json:"open_issues"`
	BySeverity     map[string]int `json:"by_severity"`
	Exploited      int            `json:"exploited"`        // proven on your system, or seen under attack
	KEV            int            `json:"kev"`              // on CISA's exploited-in-the-wild list
	Ransomware     int            `json:"ransomware"`       // CISA says ransomware crews use it
	HeldByDecision int            `json:"held_by_decision"` // suppressed by an in-force risk decision
}

type boardDecisions struct {
	InForce int `json:"in_force"`
	Lapsed  int `json:"lapsed"`  // review date passed — back on the list, awaiting a new decision
	Undated int `json:"undated"` // accepted before review dates existed; nobody is due to look again
}

type boardCoverage struct {
	TotalAssets   int      `json:"total_assets"`
	ScannedAssets int      `json:"scanned_assets"`
	NeverScanned  []string `json:"never_scanned,omitempty"` // up to 10 targets, named so they can be fixed
}

type boardReport struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Headline    string         `json:"headline"`
	Proven      boardProven    `json:"proven"`
	Exposure    boardExposure  `json:"exposure"`
	TopFixes    []fixPlanStep  `json:"top_fixes"`
	Decisions   boardDecisions `json:"decisions"`
	Coverage    boardCoverage  `json:"coverage"`
	Caveats     []string       `json:"caveats"`
}

const boardTopFixes = 5

func (d Deps) handleBoardReport(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	now := time.Now().UTC()
	rep := boardReport{GeneratedAt: now, TopFixes: []fixPlanStep{}, Caveats: []string{}}

	open, held, err := d.planFindings(ctx, tenantID, now)
	if err != nil {
		respond(w, nil, err)
		return
	}
	rep.Proven.BySeverity = map[string]int{}
	rep.Proven.HeldByDecision = held
	for _, i := range crossdetect.UnifiedIssues(open) {
		rep.Proven.OpenIssues++
		rep.Proven.BySeverity[i.Severity]++
		if i.Attacked || types.EvidenceRung(i.EvidenceRung).ClaimsExploitability() {
			rep.Proven.Exploited++
		}
		if i.KEV {
			rep.Proven.KEV++
		}
		if i.Ransomware {
			rep.Proven.Ransomware++
		}
	}

	if plan, perr := d.fixPlan(ctx, tenantID, now); perr == nil {
		n := min(boardTopFixes, len(plan.Steps))
		rep.TopFixes = plan.Steps[:n]
	}

	// The trend and its verdict, exactly as /activity computes them.
	eps, _ := d.Store.ListEpisodes(ctx, tenantID)
	acts, _ := d.Store.ListActions(ctx, tenantID)
	trend := exposuretrend.Compute(eps, acts, "")
	var obj exposuretrend.Objective
	if t, terr := d.Store.GetTenant(ctx, tenantID); terr == nil && t.ExposureObjective != nil {
		o := t.ExposureObjective
		obj = exposuretrend.Objective{Declared: o.Declared, WindowDays: o.WindowDays,
			NetPerWindow: o.NetPerWindow, MinConfirmedFixed: o.MinConfirmedFixed}
	}
	rep.Exposure.Objective = exposuretrend.Evaluate(trend, obj)
	rep.Exposure.ConfirmedFixed = trend.ConfirmedFixed
	rep.Exposure.Caveat = trend.Caveat
	cutoff := now.AddDate(0, 0, -30).Format("2006-01-02")
	for _, p := range trend.Points {
		if p.Day >= cutoff {
			rep.Exposure.Opened30 += p.Opened
			rep.Exposure.Closed30 += p.Closed
		}
	}

	if rules, rerr := d.Store.ListIgnoreRules(ctx, tenantID); rerr == nil {
		for _, ir := range rules {
			switch {
			case !ir.Suppresses(now):
				rep.Decisions.Lapsed++
			case ir.ExpiresAt.IsZero() && ir.NeedsReview():
				rep.Decisions.Undated++
				rep.Decisions.InForce++
			default:
				rep.Decisions.InForce++
			}
		}
	}

	assets, _ := d.Store.ListAssets(ctx, tenantID)
	engs, _ := d.Store.ListEngagements(ctx, tenantID)
	cov := coverage.Compute(assets, open, engs)
	rep.Coverage.TotalAssets, rep.Coverage.ScannedAssets = cov.TotalAssets, cov.ScannedAssets
	for _, a := range cov.Assets {
		if !a.Scanned && len(rep.Coverage.NeverScanned) < 10 {
			rep.Coverage.NeverScanned = append(rep.Coverage.NeverScanned, a.Target)
		}
	}

	rep.Headline = boardHeadline(rep)
	rep.Caveats = boardCaveats(rep)

	if r.URL.Query().Get("format") == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="security-board-report.md"`)
		_, _ = w.Write([]byte(renderBoardMarkdown(rep)))
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// boardHeadline is one factual sentence. It leads with what is PROVEN, because that is the part a board
// can act on and the part no scanner-count summary can say.
func boardHeadline(r boardReport) string {
	var b strings.Builder
	switch {
	case r.Coverage.ScannedAssets == 0:
		return "Nothing has been scanned yet, so there is no security position to report — an empty report " +
			"here means unmeasured, not safe."
	case r.Proven.OpenIssues == 0:
		fmt.Fprintf(&b, "No open issues across %d scanned asset(s)", r.Coverage.ScannedAssets)
	default:
		fmt.Fprintf(&b, "%d open issue(s); %d proven exploitable on your systems, %d on CISA's actively-exploited list",
			r.Proven.OpenIssues, r.Proven.Exploited, r.Proven.KEV)
	}
	if n := r.Coverage.TotalAssets - r.Coverage.ScannedAssets; n > 0 {
		fmt.Fprintf(&b, " — and %d asset(s) have never been scanned, so they are not in these numbers", n)
	}
	b.WriteString(".")
	return b.String()
}

func boardCaveats(r boardReport) []string {
	out := []string{"Closed means an issue stopped appearing in scans; only \"proven closed\" rests on a re-test."}
	if r.Proven.HeldByDecision > 0 {
		out = append(out, fmt.Sprintf("%d finding(s) are held back by a risk decision and are not counted as open.", r.Proven.HeldByDecision))
	}
	if r.Decisions.Undated > 0 {
		out = append(out, fmt.Sprintf("%d accepted risk(s) have no review date, so nobody is due to look at them again.", r.Decisions.Undated))
	}
	if !r.Exposure.Objective.Gradeable {
		out = append(out, "Exposure is not graded: "+r.Exposure.Objective.Reason)
	}
	return out
}

func renderBoardMarkdown(r boardReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security report\n\n_Generated %s_\n\n**%s**\n\n", r.GeneratedAt.Format("2 January 2006"), r.Headline)
	fmt.Fprintf(&b, "## Open issues\n\n- Open: %d (critical %d, high %d, medium %d, low %d)\n- Proven exploitable on your systems: %d\n- On CISA's actively-exploited list: %d (ransomware-linked: %d)\n\n",
		r.Proven.OpenIssues, r.Proven.BySeverity["critical"], r.Proven.BySeverity["high"], r.Proven.BySeverity["medium"],
		r.Proven.BySeverity["low"], r.Proven.Exploited, r.Proven.KEV, r.Proven.Ransomware)
	fmt.Fprintf(&b, "## Is exposure going down?\n\n- Last 30 days: %d opened, %d stopped appearing, %d proven closed by re-test (all time)\n- Objective (%s): %s\n\n",
		r.Exposure.Opened30, r.Exposure.Closed30, r.Exposure.ConfirmedFixed, r.Exposure.Objective.Target, r.Exposure.Objective.Reason)
	b.WriteString("## Top fixes\n\n")
	if len(r.TopFixes) == 0 {
		b.WriteString("Nothing open to fix.\n\n")
	}
	for _, s := range r.TopFixes {
		fmt.Fprintf(&b, "%d. **%s** — closes %d finding(s) across %d asset(s)\n", s.Order, s.Title, s.Closes, len(s.Assets))
	}
	fmt.Fprintf(&b, "\n## Risk decisions\n\n- In force: %d (with no review date: %d)\n- Lapsed and back on the list: %d\n\n",
		r.Decisions.InForce, r.Decisions.Undated, r.Decisions.Lapsed)
	fmt.Fprintf(&b, "## Coverage\n\n- %d of %d asset(s) scanned\n", r.Coverage.ScannedAssets, r.Coverage.TotalAssets)
	for _, t := range r.Coverage.NeverScanned {
		fmt.Fprintf(&b, "- Never scanned: %s\n", t)
	}
	b.WriteString("\n## What these numbers do not say\n\n")
	for _, c := range r.Caveats {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	return b.String()
}
