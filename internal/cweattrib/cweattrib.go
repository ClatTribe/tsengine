// Package cweattrib is the AI Security Engineer's missing TRIAGE tier.
//
// THE GAP IT CLOSES. A human security engineer's main job is triage — deciding what a finding IS and
// whether it matters. The AI Security Engineer persona did investigation and fixing (the second half
// of the job) while the first half ran on hand-written rules, because neither existing tier fit:
//
//   - the deterministic L1.5 hook chain CANNOT do it. §8's compliance.map keys on CWE, so a finding
//     that arrives without one gets no control mapping at all. Measured on our own corpus, a
//     keyword substrate scores 0.00 at naming a weakness class from scanner text.
//   - a frontier model per finding is too expensive. Hooks fire on every finding at emission —
//     thousands per scan.
//
// So the task fell between the two tiers and nobody owned it. This is that tier: cheap, bounded,
// per-finding classification with a deterministic disposer.
//
// WHY IT IS SAFE TO PUT A MODEL HERE. Because the model never decides anything that reaches an
// auditor. Measured on both an 8B general and an 8B security model, LLMs over-attribute badly — they
// assigned a confident weakness class to non-vulnerabilities (a licence conflict, a complexity metric,
// a cost finding) 2/6 and 6/6 of the time. A model that will not say "this is not a weakness" cannot
// be trusted to annotate compliance evidence.
//
// The design answers that directly:
//
//  1. CLOSED SET. The model may only return a CWE that already exists in the shipped crosswalk. An
//     id outside it is discarded, so a hallucinated class is structurally incapable of producing a
//     control mapping. This is the property a free-text prompt cannot give you.
//  2. THE CROSSWALK STILL DISPOSES. Attribution proposes a CWE; the existing deterministic lookup
//     turns it into controls, exactly as it does for a scanner-supplied CWE. No new path to controls
//     is created — §10 holds unchanged.
//  3. IT ONLY FILLS GAPS. A finding that already carries a CWE is never touched. The model cannot
//     overwrite what a scanner asserted.
//  4. ABSTENTION IS A FIRST-CLASS ANSWER. "NONE" is valid and expected; refusing to guess is the
//     correct behaviour on the licence conflicts and cost findings that measurably fool models.
//
// THE RESIDUAL RISK, STATED PLAINLY. The closed set blocks a class that does not EXIST. It cannot
// block a class that exists but is WRONG. Measured live: asked to classify a copyleft licensing
// conflict, one 8B model answered CWE-918 (SSRF) — a perfectly valid crosswalk key, applied to a
// finding that is not a vulnerability at all. The guard passed it, because there is nothing
// structural left to catch at that point.
//
// So the closed set is necessary and not sufficient, and the remaining defence is the model's own
// willingness to decline. That is a real property that differs sharply between models — on the same
// two cases another 8B classified the injection correctly AND declined the licence conflict. Treat
// the choice of model here as a safety decision, not a performance one, and prefer one that abstains.
// The per-role routing (platform.RoleAnalysis) is what makes that choice expressible.
package cweattrib

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// LLM is the minimal model seam (satisfied by cloudengine.LLM and the agent clients).
type LLM interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// Attributor fills in a missing CWE, constrained to a known key set.
type Attributor struct {
	LLM LLM
	// Allowed is the closed set the model's answer must land in — pass the crosswalk's own keys
	// (hooks.Compliance.MappedCWEs). An empty set disables attribution entirely rather than falling
	// back to "anything the model says", because unconstrained attribution is the failure mode this
	// package exists to prevent.
	Allowed []string
}

// Result is one attribution decision, kept explicit so the caller can log WHY nothing happened.
type Result struct {
	FindingID string
	CWE       string // "" when nothing was attributed
	// Reason is always set — an audit trail for a decision a model participated in.
	Reason string
}

var cweRe = regexp.MustCompile(`(?i)CWE[-\s]?(\d{1,5})`)

// declineTokens are the ways a model says "not a weakness class". Checked BEFORE the id, so
// "this is not CWE-89, it is a policy issue" is read as a decline rather than as CWE-89.
var declineTokens = []string{"none", "not a technical", "not applicable", "n/a", "unknown"}

// Attribute proposes a CWE for one finding. It returns "" whenever it is not confident the answer is
// both real and in-scope — silence is always an acceptable outcome here, a wrong control mapping is not.
func (a Attributor) Attribute(ctx context.Context, f types.Finding) Result {
	if len(f.CWE) > 0 {
		return Result{FindingID: f.ID, Reason: "already classified by the scanner — not overwritten"}
	}
	if a.LLM == nil || len(a.Allowed) == 0 {
		return Result{FindingID: f.ID, Reason: "no model or no allowed key set — attribution disabled"}
	}
	allowed := map[string]bool{}
	for _, c := range a.Allowed {
		allowed[strings.ToUpper(strings.TrimSpace(c))] = true
	}

	out, err := a.LLM.Generate(ctx, prompt(f, a.Allowed))
	if err != nil {
		// A transport failure is not a classification — never let it look like one.
		return Result{FindingID: f.ID, Reason: "model unavailable: " + err.Error()}
	}
	low := strings.ToLower(out)
	for _, d := range declineTokens {
		if strings.Contains(low, d) {
			return Result{FindingID: f.ID, Reason: "model declined — not a weakness class"}
		}
	}
	m := cweRe.FindStringSubmatch(out)
	if m == nil {
		return Result{FindingID: f.ID, Reason: "no parseable class in the response"}
	}
	cwe := "CWE-" + m[1]
	if !allowed[cwe] {
		// The load-bearing guard: a class we have no crosswalk entry for cannot produce a control
		// mapping, so attributing it would add an unusable annotation with a veneer of authority.
		return Result{FindingID: f.ID, Reason: cwe + " is outside the crosswalk — discarded rather than annotated"}
	}
	return Result{FindingID: f.ID, CWE: cwe, Reason: "attributed from scanner text, constrained to the crosswalk"}
}

// Fill attributes every finding that lacks a CWE, in place, and returns the decisions.
//
// max bounds the model spend per batch: the tier is meant to be cheap, and a scan that emits
// thousands of unclassified findings should not become an unbounded inference bill. Findings past the
// cap are simply left unclassified — the same state they are in today.
func (a Attributor) Fill(ctx context.Context, findings []types.Finding, max int) ([]types.Finding, []Result) {
	var results []Result
	spent := 0
	for i := range findings {
		if len(findings[i].CWE) > 0 {
			continue
		}
		if spent >= max {
			break
		}
		spent++
		r := a.Attribute(ctx, findings[i])
		results = append(results, r)
		if r.CWE != "" {
			findings[i].CWE = []string{r.CWE}
		}
	}
	return findings, results
}

// prompt asks for one class from the allowed set, and makes declining an explicit, named option.
//
// Offering the decline is not politeness — without it a model has no way to express "this is a
// licence conflict, not a vulnerability", and the measured over-attribution gets worse.
func prompt(f types.Finding, allowed []string) string {
	var b strings.Builder
	b.WriteString("You are triaging a security scanner finding that arrived without a weakness class.\n\n")
	b.WriteString("Finding:\n")
	fmt.Fprintf(&b, "  tool:        %s\n", f.Tool)
	fmt.Fprintf(&b, "  rule:        %s\n", f.RuleID)
	fmt.Fprintf(&b, "  title:       %s\n", f.Title)
	if f.Description != "" {
		fmt.Fprintf(&b, "  description: %s\n", f.Description)
	}
	if f.Endpoint != "" {
		fmt.Fprintf(&b, "  location:    %s\n", f.Endpoint)
	}
	b.WriteString("\nChoose the ONE weakness class from this list that this finding represents:\n  ")
	b.WriteString(strings.Join(allowed, ", "))
	b.WriteString("\n\nIf it is not a technical weakness — a licensing conflict, a cost or capacity issue, a code-quality\n")
	b.WriteString("metric, a business-policy discrepancy — answer exactly: NONE\n")
	b.WriteString("If the right class is not in the list above, also answer NONE.\n\n")
	b.WriteString("Answer with only the identifier (for example: CWE-79) or NONE. No explanation.\n")
	return b.String()
}
