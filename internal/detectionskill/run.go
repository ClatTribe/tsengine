package detectionskill

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// run.go executes a matched skill against a finding.
//
// The shape is the engine's standard one (CLAUDE.md §10): the model PROPOSES, this package DISPOSES.
// Everything a skill contributes arrives as untrusted context (trust.go); everything it produces is
// validated before it can mean anything (verdict.go). Between those two, the model is free to reason —
// which is the point of adopting the format at all.

// LLM is the minimal text-in/text-out seam. cloudengine.LLM satisfies it structurally, so a local
// Ollama or a per-tenant key drives skills with no extra wiring.
type LLM interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// Run executes one phase of one skill against a finding and its sibling findings.
//
// `siblings` is the evidence universe the verdict may cite — normally every finding in the incident.
// A verdict citing anything outside it is refused.
func Run(ctx context.Context, llm LLM, s Skill, phase Phase, f types.Finding, siblings []types.Finding) (Result, error) {
	if llm == nil {
		return Result{}, fmt.Errorf("detection skills need an LLM: configure one in Settings → LLM")
	}
	body := s.RenderContext(phase)
	if body == "" {
		return Result{}, fmt.Errorf("skill %q defines no %s phase", s.Name, phase)
	}
	out, err := llm.Generate(ctx, buildPrompt(s, phase, f, siblings, body))
	if err != nil {
		return Result{}, fmt.Errorf("skill %q: %w", s.Name, err)
	}
	p, err := ParseProposal(out)
	if err != nil {
		return Result{}, fmt.Errorf("skill %q: %w", s.Name, err)
	}
	return s.Validate(p, siblings)
}

// buildPrompt assembles the operator-authored frame around the untrusted skill body.
//
// Ordering matters: OUR instructions and the evidence come first, the untrusted skill last, and the
// response contract last of all — so the final thing the model reads is the contract we enforce, not
// whatever the third-party text tried to say.
func buildPrompt(s Skill, phase Phase, f types.Finding, siblings []types.Finding, skillCtx string) string {
	var b strings.Builder
	b.WriteString("You are triaging a security alert for a customer. Reach a verdict grounded ONLY in the\n")
	b.WriteString("evidence below. Do not assert anything no tool observed.\n\n")

	b.WriteString("ALERT UNDER TRIAGE\n")
	fmt.Fprintf(&b, "- id: %s\n- rule: %s\n- tool: %s\n- severity: %s\n", f.ID, nz(f.RuleID), nz(f.Tool), f.Severity)
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "- weakness: %s\n", strings.Join(f.CWE, ", "))
	}
	if f.Endpoint != "" {
		fmt.Fprintf(&b, "- location: %s\n", f.Endpoint)
	}
	if f.Title != "" {
		fmt.Fprintf(&b, "- title: %s\n", f.Title)
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "- description: %s\n", f.Description)
	}

	if len(siblings) > 0 {
		b.WriteString("\nEVIDENCE AVAILABLE (the ONLY ids you may cite)\n")
		for _, sf := range siblings {
			fmt.Fprintf(&b, "- %s: [%s] %s\n", sf.ID, nz(sf.RuleID), nz(sf.Title))
		}
	}

	b.WriteString("\n")
	b.WriteString(skillCtx) // untrusted, already framed + defanged
	b.WriteString("\n")
	b.WriteString(ProposalSchema)
	return b.String()
}

func nz(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// TuningProposal is a skill's suggested detection refinement. It is deliberately a plain record with
// no apply path: tuning reaches production only through the HITL desk like every other consequential
// change (CLAUDE.md §18.2 inv. 3). A skill can suggest silencing a rule; only a human can do it.
type TuningProposal struct {
	SkillName   string
	SkillDigest string
	FindingID   string
	RuleID      string
	Suggestion  string
}

// Tuning extracts the tuning proposal from a validated result, if the skill offered one.
func (r Result) TuningFor(f types.Finding) (TuningProposal, bool) {
	if strings.TrimSpace(r.Tuning) == "" {
		return TuningProposal{}, false
	}
	return TuningProposal{
		SkillName: r.SkillName, SkillDigest: r.SkillDigest,
		FindingID: f.ID, RuleID: f.RuleID, Suggestion: r.Tuning,
	}, true
}
