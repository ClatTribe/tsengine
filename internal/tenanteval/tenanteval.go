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
	"github.com/ClatTribe/tsengine/internal/detect"
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
	// SourceEvidenceInsufficient is the strongest case source there is, and it costs
	// nothing to collect: the re-scan said a finding was GONE and the exploit still
	// worked. Two independent verification methods disagreed, the stronger one won, and
	// the record of that disagreement is a labelled example that absence-as-evidence was
	// not enough here.
	//
	// It is a Keep case, and for a sharper reason than the others: the pipeline did not
	// merely rank this wrong, it was one step from telling a customer they were safe.
	SourceEvidenceInsufficient Source = "evidence_insufficient"
	// SourceAcceptedRisk is a suppression that CONFIRMS the finding. "We accept this
	// risk" presupposes there IS a risk, so it is a Keep case — a human agreeing the
	// finding is real and choosing not to act. It was being discarded because the
	// suppression branch only looks for false_positive, which meant the one reason a
	// customer gives that AGREES with us produced no signal at all.
	//
	// "wont_fix" is deliberately NOT here. It is ambiguous — it can mean "real but not
	// worth our time" or "not a real problem for us" — and a case source has to know
	// which answer it is recording.
	SourceAcceptedRisk Source = "accepted_risk"
	// SourceHumanVerdict is an explicit typed judgement (platform.Feedback) rather than
	// an inference from a click. It is the only source where the customer answered the
	// question we actually wanted answered.
	SourceHumanVerdict Source = "human_verdict"
)

// AllSources is the closed set, for the guard test and for the frontend's exhaustiveness —
// the same contract platformapi.AllDegradationKinds provides for degradations.
//
// SourceStarter is deliberately absent: starter cases are scored under their own arm and are
// never mixed into "agreement with your experts", so they do not appear in that list.
func AllSources() []Source {
	return []Source{
		SourceReinstated,
		SourceIgnored,
		SourceConfirmedFix,
		SourceEvidenceInsufficient,
		SourceAcceptedRisk,
		SourceHumanVerdict,
	}
}

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
// Inputs is everything a suite can be built from. A struct rather than five slice
// parameters: two adjacent []types.Finding arguments are trivially swappable at a call
// site and the compiler cannot tell, which is the kind of mistake that produces a suite
// that scores fine and means nothing.
type Inputs struct {
	Findings  []types.Finding
	Dismissed []types.Finding
	Ignores   []platform.IgnoreRule
	Actions   []platform.Action
	// Feedback are explicit human judgements. Unlike everything else here they are not
	// inferred from an action taken for another reason — someone typed an answer to the
	// question we asked — so they outrank the inferred sources when both cover one
	// finding.
	Feedback []platform.Feedback
}

// BuildSuite assembles the tenant's eval cases from their own recorded judgements.
//
// Ordering matters, because the first source to claim a finding owns it. EXPLICIT
// statements come before INFERRED ones: a person who typed "this is a false positive"
// has said something a suppression can only be read to imply, and where the two
// disagree the typed answer is the one they meant.
func BuildSuite(findings, dismissed []types.Finding, ignores []platform.IgnoreRule, actions []platform.Action) []Case {
	return BuildSuiteFrom(Inputs{Findings: findings, Dismissed: dismissed, Ignores: ignores, Actions: actions})
}

// BuildSuiteFrom is BuildSuite over the full input set.
func BuildSuiteFrom(in Inputs) []Case {
	findings, dismissed, ignores, actions := in.Findings, in.Dismissed, in.Ignores, in.Actions
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

	// 1b. Explicit judgements. These sit directly below reinstatements and ABOVE every
	// inferred source, because the customer answered the question rather than leaving us
	// to read intent into a click.
	//
	// Only the verdict about the FINDING becomes a case: Score replays the L1.5 chain and
	// asks keep-or-suppress, and an opinion about our EVIDENCE does not map onto that
	// question. It is recorded on the feedback itself and read by the verification-policy
	// corpus instead. "unclear" produces no case at all — it says the finding was
	// unreadable, which is a defect in the write-up rather than a claim about whether the
	// finding is correct, and filing it as either verdict would put words in someone's
	// mouth.
	judged := map[string]platform.Feedback{}
	for _, fb := range in.Feedback {
		judged[fb.IssueKey] = fb
	}
	if len(judged) > 0 {
		for _, f := range append(append([]types.Finding{}, findings...), dismissed...) {
			fb, ok := judged[crossdetect.DedupKey(f)]
			if !ok || seen[f.ID] {
				continue
			}
			var expect Verdict
			switch fb.Verdict {
			case platform.FeedbackReal:
				expect = Keep
			case platform.FeedbackFalsePositive:
				expect = Suppress
			default:
				continue // unclear, or a verdict we do not recognise: no case
			}
			seen[f.ID] = true
			reason := "a person judged this " + fb.Verdict
			if fb.Evidence == platform.EvidenceInsufficient {
				reason += ", and said our evidence did not show them why"
			}
			cases = append(cases, Case{
				FindingID: f.ID, RuleID: f.RuleID, Source: SourceHumanVerdict, Expect: expect,
				By: fb.By, Reason: reason, finding: f,
			})
		}
	}

	// 2. Suppressions: an issue a human marked a false positive.
	//
	// The key MUST be computed by the same function that assigned it when the issue was suppressed
	// (crossdetect.DedupKey). This branch previously rebuilt it by hand as rule_id+"|"+endpoint,
	// which is not the format: real keys are "rule|<lower rule>|<lower endpoint>", or "cve|CVE-…"
	// for anything carrying a CVE. So it matched nothing, for every tenant, and this entire source
	// of cases silently produced none — the suite looked empty rather than broken.
	ignored := map[string]platform.IgnoreRule{}
	// accepted holds the OPPOSITE verdict from the same control: a suppression whose
	// stated reason agrees the finding is real.
	accepted := map[string]platform.IgnoreRule{}
	for _, ig := range ignores {
		switch strings.ToLower(strings.TrimSpace(ig.Reason)) {
		case "false_positive":
			ignored[ig.IssueKey] = ig
		case "accepted_risk":
			accepted[ig.IssueKey] = ig
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

	// 3b. Accepted risk: the customer looked at this, agreed it was real, and decided
	// not to fix it. Same control as the false-positive suppression, opposite verdict —
	// and unlike a confirmed fix, it is an EXPLICIT statement rather than an inference
	// from someone having bothered.
	for _, f := range append(append([]types.Finding{}, findings...), dismissed...) {
		ig, ok := accepted[crossdetect.DedupKey(f)]
		if !ok || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		cases = append(cases, Case{
			FindingID: f.ID, RuleID: f.RuleID, Source: SourceAcceptedRisk, Expect: Keep,
			By: ig.By, Reason: "a person accepted this as a real risk they chose not to fix",
			finding: f,
		})
	}

	// 4. Evidence-insufficiency: an applied fix whose re-scan said "gone" while the
	// re-attack proved the exploit still ran. Free to collect — the product already does
	// both checks — and it is the only source that measures the VERIFIER rather than the
	// filter. Everything else here asks "did we rank this right"; this asks "was our
	// proof good enough", which is the question a security team is actually staking its
	// reputation on.
	insufficient := map[string]bool{}
	for _, a := range actions {
		v := a.Verification
		if v == nil || v.Disagreement != platform.DisagreeRescanMissedLiveExploit {
			continue
		}
		for _, k := range v.StillPresent {
			insufficient[k] = true
		}
	}
	if len(insufficient) > 0 {
		for _, f := range append(append([]types.Finding{}, findings...), dismissed...) {
			if seen[f.ID] || !insufficient[detect.Key(f)] {
				continue
			}
			seen[f.ID] = true
			cases = append(cases, Case{
				FindingID: f.ID, RuleID: f.RuleID, Source: SourceEvidenceInsufficient, Expect: Keep,
				Reason:  "a re-scan reported this gone and the exploit still worked — absence was not proof",
				finding: f,
			})
		}
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
