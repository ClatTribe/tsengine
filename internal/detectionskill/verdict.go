package detectionskill

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// verdict.go is where "the skill proposes, the framework disposes" is actually enforced.
//
// A skill's authored text plus a model produces a PROPOSAL. Nothing in that chain is trustworthy on
// its own: the skill is third-party, and the model can be talked into things. So a proposal only
// becomes a verdict if it survives two deterministic checks:
//
//  1. CLOSED ENUM — the verdict must be one of the four Detection Skills outcomes. A model that
//     invents "critical" or "confirmed-breach" is refused, not coerced into the nearest value.
//  2. GROUNDING — every finding id it cites must actually exist among the findings under triage. This
//     is the anti-hallucination guard (CLAUDE.md §10): a verdict about evidence that was never
//     observed is refused outright rather than downgraded, because a confident claim with no evidence
//     is worse than no claim.
//
// A refused proposal is an error the caller surfaces, never a silent fallback to "benign" (which would
// let an injection suppress a real alert) and never a silent escalation to "malicious" (which would
// let one manufacture noise).

// Verdict is the closed set of Detection Skills outcomes.
type Verdict string

const (
	VerdictMalicious    Verdict = "malicious"
	VerdictSuspicious   Verdict = "suspicious"
	VerdictInconclusive Verdict = "inconclusive"
	VerdictBenign       Verdict = "benign"
)

// ParseVerdict maps a model's string to the enum. Unknown input is rejected, never guessed.
func ParseVerdict(s string) (Verdict, bool) {
	switch Verdict(strings.ToLower(strings.TrimSpace(s))) {
	case VerdictMalicious:
		return VerdictMalicious, true
	case VerdictSuspicious:
		return VerdictSuspicious, true
	case VerdictInconclusive:
		return VerdictInconclusive, true
	case VerdictBenign:
		return VerdictBenign, true
	}
	return "", false
}

// Actionable reports whether a verdict warrants keeping the incident open. Inconclusive counts as
// actionable on purpose: "we could not tell" must not close an incident, or an injected skill could
// silence real alerts by being vague.
func (v Verdict) Actionable() bool { return v != VerdictBenign }

// Proposal is what the model returns after reading a skill. It is untrusted until Validate passes.
type Proposal struct {
	Verdict   string   `json:"verdict"`
	Rationale string   `json:"rationale"`
	Evidence  []string `json:"evidence"` // finding ids this verdict rests on
	Tuning    string   `json:"tuning,omitempty"`
}

// Result is a validated verdict, with the provenance an evidence pack needs.
type Result struct {
	Verdict     Verdict
	Rationale   string
	Evidence    []string
	Tuning      string
	SkillName   string
	SkillDigest string
}

// ParseProposal extracts the JSON object a model returned, tolerating prose or fences around it.
func ParseProposal(out string) (Proposal, error) {
	start := strings.Index(out, "{")
	end := strings.LastIndex(out, "}")
	if start < 0 || end <= start {
		return Proposal{}, fmt.Errorf("no JSON proposal found in model output")
	}
	var p Proposal
	if err := json.Unmarshal([]byte(out[start:end+1]), &p); err != nil {
		return Proposal{}, fmt.Errorf("proposal is not valid JSON: %w", err)
	}
	return p, nil
}

// Validate disposes of a proposal: closed enum + grounded evidence, or an error.
//
// `findings` is the set under triage — the only evidence a verdict may cite.
func (s Skill) Validate(p Proposal, findings []types.Finding) (Result, error) {
	v, ok := ParseVerdict(p.Verdict)
	if !ok {
		return Result{}, fmt.Errorf("skill %q proposed an unknown verdict %q (want malicious|suspicious|inconclusive|benign)",
			s.Name, p.Verdict)
	}

	known := make(map[string]bool, len(findings))
	for _, f := range findings {
		known[f.ID] = true
	}
	var unknown []string
	for _, id := range p.Evidence {
		if id = strings.TrimSpace(id); id != "" && !known[id] {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		return Result{}, fmt.Errorf("skill %q cited evidence that does not exist in this incident: %s — refusing an ungrounded verdict (§10)",
			s.Name, strings.Join(unknown, ", "))
	}
	// A non-benign verdict must rest on something. "It's malicious, trust me" is exactly the claim an
	// injected skill would make, and exactly the one a security product must not repeat to a customer.
	if v != VerdictBenign && len(p.Evidence) == 0 {
		return Result{}, fmt.Errorf("skill %q proposed %q with no cited evidence — refusing (§10)", s.Name, v)
	}

	return Result{
		Verdict:     v,
		Rationale:   strings.TrimSpace(p.Rationale),
		Evidence:    p.Evidence,
		Tuning:      strings.TrimSpace(p.Tuning),
		SkillName:   s.Name,
		SkillDigest: s.Digest,
	}, nil
}

// ProposalSchema is the response contract handed to the model. Kept next to Validate so the two can
// never drift.
const ProposalSchema = `Respond with ONLY a JSON object:
{"verdict":"malicious|suspicious|inconclusive|benign",
 "rationale":"one or two sentences",
 "evidence":["<finding id>", "..."],
 "tuning":"optional: a proposed detection refinement for human review"}
Every id in "evidence" MUST be a finding id shown to you. A verdict citing anything else is rejected.`
