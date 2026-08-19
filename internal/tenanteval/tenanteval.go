// Package tenanteval builds an evaluation suite from a tenant's OWN history, and scores the
// current filtering configuration against it.
//
// WHY THIS EXISTS. Public benchmarks (OWASP Benchmark, WAVSEP, XBOW) measure the engine against
// somebody else's corpus. They are necessary and we run them, but they cannot answer the question a
// security engineer actually has, which is "does this still catch the thing that bit US?" — and they
// are a vendor's number about a vendor's corpus, which is precisely the claim practitioners have
// stopped believing (reliance on AI pentesting fell to 9% in 2026 from 29%).
//
// The cases here are not authored by us. Every one is a judgement the CUSTOMER already made on their
// own estate:
//
//   - a finding a human REINSTATED after the filter dropped it — an expert said "this is real", so
//     the filter must not drop it again;
//   - an issue a human IGNORED as a false positive — an expert said "this is noise", so suppressing
//     it is correct;
//   - a finding whose fix a re-scan CONFIRMED closed — it was real enough to be worth fixing, so it
//     must still be caught.
//
// Scoring re-runs the CURRENT L1.5 chain over each case and compares its verdict with the human's.
// The number therefore means something specific and checkable: how often today's configuration
// agrees with this tenant's own experts about this tenant's own findings. It is proof the customer
// generates themselves, from data they produced, which is the only kind that survives scepticism.
//
// Grounded (§10): a tenant with no history gets NO score. An eval suite with no cases would report
// 100% agreement, which is a number that rises as a customer does less — exactly the sort of metric
// this codebase keeps refusing to emit.
package tenanteval

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/l15"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Verdict is what a case expects the pipeline to do with a finding.
type Verdict string

const (
	// Keep: a human established this finding is real. Dropping it is a false negative.
	Keep Verdict = "keep"
	// Suppress: a human established this finding is noise. Surfacing it is a false positive.
	Suppress Verdict = "suppress"
)

// Source records WHERE a case's ground truth came from, so a reader can weigh it. A reinstatement is
// a direct correction of the filter; a confirmed fix is weaker evidence about filtering (nobody
// disputed it) but strong evidence the finding mattered.
type Source string

const (
	SourceReinstated   Source = "reinstated"    // a human overrode a dismissal
	SourceIgnored      Source = "ignored"       // a human suppressed it as a false positive
	SourceConfirmedFix Source = "confirmed_fix" // a re-scan proved the fix closed it
)

// Case is one graded example drawn from the tenant's own history.
type Case struct {
	FindingID string        `json:"finding_id"`
	RuleID    string        `json:"rule_id"`
	Source    Source        `json:"source"`
	Expect    Verdict       `json:"expect"`
	By        string        `json:"by,omitempty"`     // the human whose judgement this is, when recorded
	Reason    string        `json:"reason,omitempty"` // why they judged it so
	finding   types.Finding // the original, replayed through the chain at scoring time
}

// Failure is a case where the current configuration disagrees with the tenant's own expert.
type Failure struct {
	Case
	Got Verdict `json:"got"`
}

// Result is the tenant's score against their own suite.
type Result struct {
	Cases    int       `json:"cases"`
	Passed   int       `json:"passed"`
	Failures []Failure `json:"failures"`
	// BySource lets a reader see WHICH kind of judgement the configuration is failing — disagreeing
	// with reinstatements (dropping findings experts called real) is a different and worse problem
	// than disagreeing with suppressions.
	BySource map[Source]int `json:"by_source"`
	// Note explains an empty or thin suite rather than letting a vacuous score stand.
	Note string `json:"note,omitempty"`
}

// Agreement is the share of cases where the pipeline matched the human. Returns 0 and false when
// there are no cases — a suite with nothing in it has no score, and reporting 100% would reward a
// customer for never correcting anything.
func (r Result) Agreement() (float64, bool) {
	if r.Cases == 0 {
		return 0, false
	}
	return float64(r.Passed) / float64(r.Cases), true
}

// BuildSuite derives the tenant's eval cases from what they have already decided.
//
// findings is the tenant's current finding set, dismissed the findings the L1.5 chain dropped
// (Engagement.L15Dismissed), ignores their suppression rules, and actions their remediation record.
func BuildSuite(findings, dismissed []types.Finding, ignores []platform.IgnoreRule, actions []platform.Action) []Case {
	var cases []Case
	seen := map[string]bool{}

	// 1. Reinstatements: the strongest signal we have. A human looked at something the filter threw
	// away and put it back, which is a direct, attributed correction of the pipeline.
	for _, f := range findings {
		if f.DiscoveryMethod == nil || f.DiscoveryMethod.Primary != platform.DiscoveryHumanReinstated || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		cases = append(cases, Case{
			FindingID: f.ID, RuleID: f.RuleID, Source: SourceReinstated, Expect: Keep,
			Reason: "a person reinstated this after the filter dropped it", finding: f,
		})
	}

	// 2. Suppressions: an issue a human marked a false positive.
	//
	// The key MUST be computed by the same function that assigned it when the issue was suppressed
	// (crossdetect.DedupKey). This branch previously rebuilt it by hand as rule_id+"|"+endpoint,
	// which is not the format: real keys are "rule|<lower rule>|<lower endpoint>", or "cve|CVE-…"
	// for anything carrying a CVE. So it matched nothing, for every tenant, and this entire source
	// of cases silently produced none — the suite looked empty rather than broken.
	ignored := map[string]platform.IgnoreRule{}
	for _, ig := range ignores {
		if strings.EqualFold(strings.TrimSpace(ig.Reason), "false_positive") {
			ignored[ig.IssueKey] = ig
		}
	}
	for _, f := range append(append([]types.Finding{}, findings...), dismissed...) {
		ig, ok := ignored[crossdetect.DedupKey(f)]
		if !ok || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		cases = append(cases, Case{
			FindingID: f.ID, RuleID: f.RuleID, Source: SourceIgnored, Expect: Suppress,
			By: ig.By, Reason: ig.Note, finding: f,
		})
	}

	// 3. Confirmed fixes: a re-scan proved the remediation closed it, so the finding was real enough
	// to be worth an engineer's time. Weaker evidence about FILTERING than a reinstatement — nobody
	// disputed it — but it is the tenant's own record that this class matters to them.
	fixed := map[string]bool{}
	for _, a := range actions {
		if a.Verification != nil && a.Verification.Status == platform.FixStatusFixed && a.FindingID != "" {
			fixed[a.FindingID] = true
		}
	}
	for _, f := range findings {
		if !fixed[f.ID] || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		cases = append(cases, Case{
			FindingID: f.ID, RuleID: f.RuleID, Source: SourceConfirmedFix, Expect: Keep,
			Reason: "a re-scan confirmed the fix closed this", finding: f,
		})
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].FindingID < cases[j].FindingID })
	return cases
}

// Score replays each case through the CURRENT L1.5 chain and compares the outcome with the human's
// judgement. Nothing here is a simulation: it is the same l15.Enrich the product runs on every scan.
func Score(cases []Case) Result {
	res := Result{Cases: len(cases), BySource: map[Source]int{}, Failures: []Failure{}}
	if len(cases) == 0 {
		res.Note = "No graded cases yet. A suite is built from decisions you have made — reinstating a " +
			"suppressed finding, marking one a false positive, or confirming a fix closed one. Until then " +
			"there is nothing to score, which is not the same as scoring well."
		return res
	}
	for _, c := range cases {
		got := Suppress
		// One finding at a time: the chain's cross-finding passes (merge, corroboration) would
		// otherwise let unrelated cases change each other's verdicts, and a case must stand alone.
		if out := l15.Enrich([]types.Finding{c.finding}); len(out) > 0 {
			got = Keep
		}
		if got == c.Expect {
			res.Passed++
			continue
		}
		res.BySource[c.Source]++
		res.Failures = append(res.Failures, Failure{Case: c, Got: got})
	}
	if res.Cases < 5 {
		res.Note = "This suite is small, so the score moves a lot per case. It grows as you correct the " +
			"system — each reinstatement, suppression and confirmed fix adds a graded example."
	}
	return res
}
