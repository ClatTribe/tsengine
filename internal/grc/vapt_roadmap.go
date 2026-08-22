package grc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/fixunit"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The remediation roadmap — the section a real pentest report CLOSES with, and the one thing the
// per-finding list cannot give a reader: the ORDER to do the work in.
//
// A severity-sorted list of findings is not a plan. It says nothing about which items are the same
// job (four CVEs in one package are one upgrade), and its order is wrong for a team with a week:
// severity alone puts an unproven "critical" pattern match above a high-severity vulnerability we
// have an exploit for. This turns the findings into an ordered, deduplicated set of STEPS.
//
// TWO REFUSALS MAKE IT HONEST.
//
// 1. NO EFFORT OR TIME ESTIMATES. Every real remediation plan a consultancy writes has an "effort:
// medium / 2 days" column, and we have no basis for one. We do not know the codebase, the release
// process, the test coverage, or who is free. An invented estimate is the most quotable number in
// the document and would be the least grounded thing in it — a customer plans a sprint around it
// (§10). What we CAN state is what closes what, and in which order, which is the half that needs a
// scanner rather than a guess.
//
// 2. THE GROUPING IS NOT OURS TO INVENT — it comes from internal/fixunit, the same definition the
// remediation engine uses to open bulk pull requests. If the roadmap grouped separately, the plan
// the customer executes and the PRs the product opens would describe different work.

// RemediationStep is one unit of work in the plan: a single change, the findings it closes, and
// the grounded reason it sits where it does.
type RemediationStep struct {
	Order    int      `json:"order"`
	Title    string   `json:"title"`           // what to do
	Action   string   `json:"action"`          // the standard fix for the class
	Severity string   `json:"severity"`        // worst severity in the group
	Closes   int      `json:"closes"`          // how many findings this one change resolves
	Findings []string `json:"findings"`        // their ids — every claim traceable (§10)
	Why      []string `json:"why,omitempty"`   // the grounded signals that set this priority
	Where    []string `json:"where,omitempty"` // up to a few affected locations
	FixReady bool     `json:"fix_ready"`       // a remediation is already prepared, awaiting approval
	Validate bool     `json:"validate"`        // unconfirmed-only: verify it is real before spending effort
}

// BuildRoadmap turns findings into the ordered remediation plan. Deterministic and pure.
func BuildRoadmap(findings []types.Finding, fixReady map[string]bool) []RemediationStep {
	type scored struct {
		step RemediationStep
		rank int  // worst severity rank in the group
		sig  int  // exploitation-evidence tier
		auto bool // CISA SSVC: an attacker can automate this
		seq  int  // first-seen, for a stable tiebreak
	}
	var all []scored
	for i, g := range fixunit.GroupBy(findings) {
		if len(g.Findings) == 0 {
			continue
		}
		st := RemediationStep{Validate: true}
		worstRank, bestSig := -1, 0
		var worst types.Finding
		seen := map[string]bool{}
		for _, f := range g.Findings {
			st.Closes++
			st.Findings = append(st.Findings, f.ID)
			if fixReady[f.ID] {
				st.FixReady = true
			}
			if isVerified(f) {
				st.Validate = false // at least one finding here is confirmed
			}
			if r := types.Severity(f.Severity).Rank(); r > worstRank {
				worstRank, worst = r, f
			}
			if s := evidenceTier(f); s > bestSig {
				bestSig = s
			}
			if f.Endpoint != "" && !seen[f.Endpoint] && len(st.Where) < 4 {
				seen[f.Endpoint] = true
				st.Where = append(st.Where, f.Endpoint)
			}
		}
		st.Severity = string(worst.Severity)
		st.Title = stepTitle(g, worst)
		st.Action = stepAction(g, worst)
		st.Why = stepWhy(g, st)
		all = append(all, scored{step: st, rank: worstRank, sig: bestSig, auto: automatable(g.Findings), seq: i})
	}

	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		// Unconfirmed-only work goes LAST regardless of its severity. Sending a team to chase a
		// pattern match ahead of a vulnerability we have proof for is how a plan wastes the week
		// it was written for — and the finding may not be real.
		if a.step.Validate != b.step.Validate {
			return !a.step.Validate
		}
		// Exploitation evidence outranks severity. A high we PROVED beats a critical nobody has
		// demonstrated: severity is a statement about the worst case, evidence about this estate.
		if a.sig != b.sig {
			return a.sig > b.sig
		}
		if a.rank != b.rank {
			return a.rank > b.rank
		}
		// Between two steps the evidence and severity cannot separate, an automatable one goes
		// first: it reaches the whole estate rather than one target at a time.
		if a.auto != b.auto {
			return a.auto
		}
		// A change that closes more findings first — same job, more of the estate cleared.
		if a.step.Closes != b.step.Closes {
			return a.step.Closes > b.step.Closes
		}
		return a.seq < b.seq
	})

	out := make([]RemediationStep, 0, len(all))
	for i, s := range all {
		s.step.Order = i + 1
		out = append(out, s.step)
	}
	return out
}

// evidenceTier ranks how strongly a finding is known to be exploitable IN PRACTICE — the axis
// severity does not carry. Higher wins. Each rung is a real recorded fact, never a heuristic:
// a captured PoC, CISA's ransomware marking, a KEV listing, a published weapon.
func evidenceTier(f types.Finding) int {
	if poc, _ := extractPoC(f.Description); poc != "" {
		return 6 // we exploited it here
	}
	if ti := f.ThreatIntel; ti != nil {
		if ti.KEV != nil && ti.KEV.Ransomware {
			return 5
		}
		if ti.KEV != nil && ti.KEV.Listed {
			return 4
		}
		// CISA saying exploitation is ACTIVE is the same claim KEV makes, from the same authority,
		// for a CVE it has not catalogued — KEV covers ~1,700 CVEs and SSVC reaches far beyond it.
		// Without this rung a vulnerability CISA says is being exploited right now ranked BELOW a
		// mere published PoC, because the absence of evidence in our KEV feed read as evidence of
		// absence. Below KEV itself, which additionally carries a federal remediation mandate —
		// the same ordering internal/threatinformed uses to rank probes (KEV +100, SSVC-active +75).
		if ti.SSVC != nil && ti.SSVC.Exploitation == "active" {
			return 3
		}
		if len(ti.Exploits) > 0 {
			return 2
		}
	}
	return 0
}

// automatable reports CISA's SSVC assessment that an attacker can automate steps 1-4 of the kill
// chain against this finding — the difference between a vulnerability exploited by hand against one
// target and one that can be driven across an estate.
func automatable(fs []types.Finding) bool {
	for _, f := range fs {
		if ti := f.ThreatIntel; ti != nil && ti.SSVC != nil && ti.SSVC.Automatable == "yes" {
			return true
		}
	}
	return false
}

// stepTitle names the change. A package group names the upgrade (mirroring the bulk-PR title, so
// the plan and the pull request read the same); otherwise the finding class and its scale.
func stepTitle(g fixunit.Group, worst types.Finding) string {
	if pkg := strings.TrimPrefix(g.Key, "pkg:"); strings.HasPrefix(g.Key, "pkg:") {
		if fixed := bestFixed(g.Findings); fixed != "" {
			return fmt.Sprintf("Upgrade %s → %s", pkg, fixed)
		}
		return fmt.Sprintf("Update %s", pkg)
	}
	if n := len(g.Findings); n > 1 {
		return fmt.Sprintf("%s (%d occurrences)", nzTitle(worst), n)
	}
	return nzTitle(worst)
}

// stepAction is what to actually DO. For a package group that is the upgrade — not the CWE-class
// advice, which for a dependency CVE is the wrong instruction: "never deserialize untrusted input"
// is guidance for the library's author, while the customer's fix is a version bump. Only ever a
// version some scanner really reported (§10); with no fixed version upstream, say that rather than
// invent an upgrade target.
func stepAction(g fixunit.Group, worst types.Finding) string {
	if strings.HasPrefix(g.Key, "pkg:") {
		pkg := strings.TrimPrefix(g.Key, "pkg:")
		if fixed := bestFixed(g.Findings); fixed != "" {
			return fmt.Sprintf("Upgrade %s to %s (or later) and re-scan to confirm the CVEs no longer resolve.", pkg, fixed)
		}
		return fmt.Sprintf("No upstream fix is published for %s yet — mitigate (restrict exposure, "+
			"apply a vendor workaround) and track the advisory until a patched version ships.", pkg)
	}
	return remediationFor(worst.CWE, worst.Tool)
}

func nzTitle(f types.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	return f.RuleID
}

// bestFixed returns the highest upstream fixed version across the group — the single upgrade that
// clears all of it. Only ever a version a scanner actually reported.
func bestFixed(fs []types.Finding) string {
	best := ""
	for _, f := range fs {
		v := f.ToolArgs["fixed_version"]
		if v == "" {
			continue
		}
		if best == "" || semverLess(best, v) {
			best = v
		}
	}
	return best
}

// semverLess compares dot-separated versions by the leading integer of each segment, so
// 4.17.21 > 4.17.19 (which a lexical compare gets wrong). Dependency-free; the reviewer confirms
// the upgrade before it merges.
func semverLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x = leadingNum(as[i])
		}
		if i < len(bs) {
			y = leadingNum(bs[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func leadingNum(s string) int {
	n, end := 0, 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		n = n*10 + int(s[end]-'0')
		end++
	}
	return n
}

// stepWhy states, in the customer's words, the recorded facts that put this step where it is.
// Every entry corresponds to a real field on a real finding — the plan's order is auditable, not
// an opaque score.
func stepWhy(g fixunit.Group, st RemediationStep) []string {
	var why []string
	add := func(s string) {
		for _, w := range why {
			if w == s {
				return
			}
		}
		why = append(why, s)
	}
	for _, f := range g.Findings {
		if poc, _ := extractPoC(f.Description); poc != "" {
			add("exploitation-proven — a working proof-of-concept was captured against this")
		}
		if ti := f.ThreatIntel; ti != nil && ti.KEV != nil {
			if ti.KEV.Ransomware {
				add("ransomware-linked — CISA records this CVE in ransomware campaigns")
			}
			if ti.KEV.Listed {
				add("actively exploited in the wild (CISA KEV)")
			}
			if !ti.KEV.DueDate.IsZero() {
				add("CISA remediation deadline " + ti.KEV.DueDate.UTC().Format("2006-01-02"))
			}
		}
		if ti := f.ThreatIntel; ti != nil && ti.SSVC != nil {
			if ti.SSVC.Exploitation == "active" {
				add("CISA assesses exploitation as ACTIVE for this CVE (SSVC)")
			}
			if ti.SSVC.Automatable == "yes" {
				add("CISA assesses this as automatable (SSVC) — it scales across an estate, not one target at a time")
			}
		}
		if ti := f.ThreatIntel; ti != nil && ti.WeaponRank != "" {
			add("a ready-to-run exploit module exists (Metasploit, rated " + ti.WeaponRank + ")")
		}
	}
	if st.Closes > 1 {
		add(fmt.Sprintf("one change closes %d findings", st.Closes))
	}
	if st.FixReady {
		add("a fix is already prepared and awaiting your approval")
	}
	if st.Validate {
		add("unconfirmed (single-tool pattern match) — validate it is real before spending effort")
	}
	return why
}

// countNoun renders "1 finding" / "N findings" — the same number-agreement discipline the rest of
// the report follows; "1 finding(s)" on a customer deliverable reads as generated.
func countNoun(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// RenderRoadmapMarkdown renders the plan section. Empty when there is nothing to do — a heading
// over no steps reads like an omission.
func RenderRoadmapMarkdown(steps []RemediationStep) string {
	if len(steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n## Remediation plan\n\n")
	b.WriteString("The findings above, grouped into the changes that fix them and ordered by what to do first. " +
		"Priority is set by evidence of real exploitability (a captured proof-of-concept, then CISA's " +
		"actively-exploited catalogue) ahead of severity alone, so proven risk outranks theoretical worst case. " +
		"Unconfirmed leads are listed last — validate them before spending effort. " +
		"**No effort or time estimates are given: we cannot see your codebase, release process, or team, " +
		"and an invented estimate is the one number in this report that nothing would support.**\n\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "### %d. %s\n\n", s.Order, s.Title)
		fmt.Fprintf(&b, "- **Severity:** %s · **Closes:** %s", strings.ToUpper(s.Severity), countNoun(s.Closes, "finding", "findings"))
		if s.FixReady {
			b.WriteString(" · **fix prepared, awaiting approval**")
		}
		b.WriteString("\n")
		if len(s.Why) > 0 {
			fmt.Fprintf(&b, "- **Why here:** %s\n", strings.Join(s.Why, "; "))
		}
		if len(s.Where) > 0 {
			fmt.Fprintf(&b, "- **Where:** %s\n", "`"+strings.Join(s.Where, "`, `")+"`")
		}
		if s.Action != "" {
			fmt.Fprintf(&b, "- **Fix:** %s\n", s.Action)
		}
		fmt.Fprintf(&b, "- **Resolves:** %s\n\n", strings.Join(s.Findings, ", "))
	}
	return b.String()
}
