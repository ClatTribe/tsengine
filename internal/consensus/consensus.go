// Package consensus is the multi-agent false-positive validator (the Synthesia "3 independent
// coding agents, odd number, majority breaks ties" pattern). It is for the AMBIGUOUS middle a
// scanner produces — findings with no clean deterministic predicate to verify (the engine's
// verifyGate/§10 handles those). Instead of trusting one LLM's say-so (nondeterministic), an
// ODD panel of independent jurors each judges the finding, and CODE takes the majority — so a
// single model's hallucination can't flip a verdict. Each juror cites the finding's evidence
// (§10 grounding); the decision is by vote, not by any one agent.
package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Verdict is one juror's independent call on a finding.
type Verdict struct {
	FalsePositive bool    `json:"false_positive"`
	Confidence    float64 `json:"confidence"` // 0..1
	Rationale     string  `json:"rationale"`  // grounded in the finding's evidence
}

// Juror independently judges whether a finding is a false positive. Production: a single,
// narrowly-scoped LLM call (LLMJuror); tests: a deterministic fake. A juror that returns an
// error casts NO vote (it is skipped) — a malformed agent never sways the panel.
type Juror interface {
	Judge(ctx context.Context, f types.Finding) (Verdict, error)
}

// Decision is the panel's consensus over a finding.
type Decision struct {
	FalsePositive bool      `json:"false_positive"` // the majority call
	Votes         int       `json:"votes"`          // jurors that returned a valid verdict
	FPVotes       int       `json:"fp_votes"`       // how many called it a false positive
	Agreement     float64   `json:"agreement"`      // |majority| / votes (1.0 = unanimous)
	Unanimous     bool      `json:"unanimous"`
	Rationales    []string  `json:"rationales"` // every juror's reasoning — the audit trail
	Verdicts      []Verdict `json:"-"`          // the raw verdicts (not serialized)
}

// Validate runs a panel of independent jurors over a finding and returns the majority
// decision. Use an ODD number of jurors so a clean majority exists; on a tie (possible only
// when some jurors error out, leaving an even count) the decision FAILS OPEN — NOT a false
// positive — so a real finding is never silently dropped on a deadlocked or failed panel.
func Validate(ctx context.Context, f types.Finding, jurors []Juror) Decision {
	d := Decision{}
	for _, j := range jurors {
		if j == nil {
			continue
		}
		v, err := j.Judge(ctx, f)
		if err != nil {
			continue // a juror error casts no vote
		}
		d.Votes++
		d.Verdicts = append(d.Verdicts, v)
		if r := strings.TrimSpace(v.Rationale); r != "" {
			d.Rationales = append(d.Rationales, r)
		}
		if v.FalsePositive {
			d.FPVotes++
		}
	}
	if d.Votes == 0 {
		return d // no votes → fail open (FalsePositive = false)
	}
	tpVotes := d.Votes - d.FPVotes
	// Strict majority. A tie keeps the finding (fail open).
	d.FalsePositive = d.FPVotes > tpVotes
	majority := tpVotes
	if d.FPVotes > tpVotes {
		majority = d.FPVotes
	}
	d.Agreement = float64(majority) / float64(d.Votes)
	d.Unanimous = d.FPVotes == 0 || tpVotes == 0
	return d
}

// Complete is the minimal LLM call the LLMJuror needs: a prompt in, a completion out. In
// production it wraps the tenant's configured LLM (platformapi.ResolveTenantLLM) or the env
// LLM; tests inject a fake. Keeping this a function keeps the package LLM-vendor-agnostic and
// fully unit-testable without a network call.
type Complete func(ctx context.Context, prompt string) (string, error)

// LLMJuror judges a finding via one narrowly-scoped LLM call. Persona biases the angle so an
// odd panel of LLMJurors gives genuinely independent perspectives (not N identical calls).
type LLMJuror struct {
	Complete Complete
	Persona  string
}

// Personas are three independent FP-review angles — the out-of-the-box odd panel.
var Personas = []string{
	"a skeptical reviewer who assumes the scanner is noisy until the evidence proves otherwise",
	"an exploitation-focused reviewer who asks whether this is actually reachable and exploitable in context",
	"a context-focused reviewer who weighs the asset's sensitivity and whether the pattern applies here at all",
}

// DefaultJurors builds the standard odd (3) panel of independent LLM jurors over one Complete.
func DefaultJurors(complete Complete) []Juror {
	js := make([]Juror, 0, len(Personas))
	for _, p := range Personas {
		js = append(js, LLMJuror{Complete: complete, Persona: p})
	}
	return js
}

// Judge prompts the model for a strict-JSON verdict and parses it. A nil Complete, a call
// error, or an unparseable response returns an error so Validate skips this juror (no vote) —
// a broken juror never sways the panel.
func (j LLMJuror) Judge(ctx context.Context, f types.Finding) (Verdict, error) {
	if j.Complete == nil {
		return Verdict{}, fmt.Errorf("consensus: nil Complete")
	}
	out, err := j.Complete(ctx, j.prompt(f))
	if err != nil {
		return Verdict{}, err
	}
	return parseVerdict(out)
}

func (j LLMJuror) prompt(f types.Finding) string {
	var b strings.Builder
	b.WriteString("You are ")
	b.WriteString(j.Persona)
	b.WriteString(". Judge ONE security finding: is it a TRUE positive (a real, valid issue worth a developer's time) or a FALSE positive (noise / not applicable / not exploitable)?\n\n")
	fmt.Fprintf(&b, "rule_id: %s\ntool: %s\nseverity: %s\ncwe: %s\nendpoint: %s\ntitle: %s\ndescription: %s\n\n",
		f.RuleID, f.Tool, f.Severity, strings.Join(f.CWE, ","), f.Endpoint, f.Title, f.Description)
	b.WriteString("Ground your rationale ONLY in the evidence above — do not invent facts. ")
	b.WriteString(`Reply with ONLY JSON: {"false_positive": <bool>, "confidence": <0.0-1.0>, "rationale": "<one sentence>"}.`)
	return b.String()
}

// parseVerdict tolerantly extracts the JSON verdict from a completion (models often wrap it in
// prose or fences). Unparseable → error (the juror is skipped, never a silent false vote).
func parseVerdict(out string) (Verdict, error) {
	s := strings.TrimSpace(out)
	if i, jx := strings.Index(s, "{"), strings.LastIndex(s, "}"); i >= 0 && jx > i {
		s = s[i : jx+1]
	}
	var v Verdict
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return Verdict{}, fmt.Errorf("consensus: unparseable verdict: %w", err)
	}
	if v.Confidence < 0 {
		v.Confidence = 0
	}
	if v.Confidence > 1 {
		v.Confidence = 1
	}
	return v, nil
}
