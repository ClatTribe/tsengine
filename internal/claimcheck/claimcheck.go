// Package claimcheck pins the product's externally-facing headline numbers.
//
// THE GAP THIS CLOSES. Every "best-in-breed" claim tsengine makes rests on a number — SCuBA 0.993,
// XBOW 85.6%, SAST 46.5% Youden, 96% crosswalk corroboration — and NOT ONE of them was pinned by a
// test. They lived only in prose, so nothing failed when the code moved underneath them and nothing
// noticed when two documents disagreed.
//
// That is not hypothetical. ADR 0024 had to record that CLAUDE.md's 0.753 and the roadmap's 0.322 for
// the SAME metric were both stale, three documents disagreeing about the number the identity claim
// rests on. §14.2 rule 6 says a guard that cannot see its subject must FAIL rather than pass
// vacuously; the headline claims had no guard at all, which is the same defect with the guard removed
// entirely — drift is silent and permanent by default.
//
// The registry below is the single place a headline number is declared, and claimcheck_test.go
// enforces three things: a RECOMPUTABLE claim still computes to its stated value (so improving the
// product forces the document to be updated rather than letting it rot); the claim's home document
// exists and states it (a missing file FAILS, it does not skip); and a superseded value appears in
// NO scanned document (which is exactly the bug above).
//
// A claim that cannot be recomputed in CI — XBOW needs a live LLM and deployed targets, SAST needs
// the OWASP Benchmark corpus — is registered with Recompute nil and a Source naming what produced it.
// That is deliberately not a loophole: the consistency and staleness guards still apply, and Source
// is required, so a number can never enter the product with no provenance at all.
package claimcheck

import "github.com/ClatTribe/tsengine/internal/bench"

// Docs is the document set scanned for stale values. Every file here must exist — a claims guard that
// silently stops reading a document it was written to police is worse than no guard, because the
// green tick now covers less than anyone reading it believes (§14.2 rule 6).
var Docs = []string{
	"CLAUDE.md",
	"arch.md",
	"docs/adr/0024-best-in-breed-coverage-gaps.md",
	"docs/specialist-roadmap.md",
}

// Claim is one externally-facing headline number.
type Claim struct {
	// Name is the metric's stable id.
	Name string
	// Value is the CANONICAL rendering as it appears in prose ("0.993", "85.6", "96%"). Kept as a
	// string because that is the form the documents carry and the form a reader compares.
	Value string
	// Source states what established the number — a recomputation, or the external run that produced
	// it. Required: a headline number with no provenance is an assertion.
	Source string
	// Home is the document that MUST state this value. One home rather than "every document", because
	// requiring every doc to carry every number creates churn without catching anything; the staleness
	// ban below is what actually enforces agreement.
	Home string
	// Superseded are earlier values for THIS metric that must no longer appear in any scanned
	// document. This is the guard that catches the real failure: a number improving in the code while
	// an old value keeps being quoted somewhere else.
	Superseded []string
	// Recompute returns the current value and true when the claim can be recomputed offline in CI.
	// Nil when it cannot — see the package comment.
	Recompute func() float64
	// Format is the fmt verb used to render a recomputed value for comparison with Value.
	Format string
}

// Registry is every headline number the product states externally.
func Registry() []Claim {
	return []Claim{
		{
			Name:   "scuba_detection_recall",
			Value:  "0.993",
			Source: "recomputed offline from bench.ScoreSCuBA over the transcribed CISA SCuBA catalogue (145/146 detectable)",
			Home:   "docs/adr/0024-best-in-breed-coverage-gaps.md",
			// 0.322 → 0.753 → 0.993 over successive passes. Both earlier values were still being
			// quoted after the number moved, which is the defect this package exists to prevent.
			Superseded: []string{"0.753", "0.322"},
			Recompute:  func() float64 { return bench.ScoreSCuBA(bench.SCuBACatalog()).Recall() },
			Format:     "%.3f",
		},
		{
			Name:       "scuba_shall_recall",
			Value:      "0.990",
			Source:     "recomputed offline from bench.ScoreSCuBA, mandatory-SHALL subset (100/101)",
			Home:       "docs/adr/0024-best-in-breed-coverage-gaps.md",
			Superseded: []string{"0.842", "0.426"},
			Recompute:  func() float64 { return bench.ScoreSCuBA(bench.SCuBACatalog()).ShallRecall() },
			Format:     "%.3f",
		},
		{
			Name:   "xbow_flag_capture",
			Value:  "85.6",
			Source: "tsbench xbow over XBOW's own 104-benchmark suite (89/104); NOT recomputable in CI — needs a capable LLM and the deployed benchmark targets",
			Home:   "docs/adr/0024-best-in-breed-coverage-gaps.md",
		},
		{
			Name:   "sast_youden",
			Value:  "46.5",
			Source: "OWASP BenchmarkJava, all 2,740 cases; NOT recomputable in CI — needs the OWASP Benchmark corpus",
			Home:   "docs/adr/0024-best-in-breed-coverage-gaps.md",
		},
		{
			Name:   "iam_vulnerable_recall",
			Value:  "64.5%",
			Source: "BishopFox IAM-Vulnerable, ~31 named privesc paths; NOT recomputable in CI — needs IAM_VULNERABLE_DIR",
			Home:   "CLAUDE.md",
		},
		{
			Name:   "rhino_gcp_recall",
			Value:  "65.2%",
			Source: "RhinoSecurityLabs GCP privesc catalogue, 23 methods; NOT recomputable in CI — needs RHINO_GCP_CATALOGUE",
			Home:   "CLAUDE.md",
		},
	}
}
