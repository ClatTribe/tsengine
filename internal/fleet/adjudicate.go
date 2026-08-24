package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// adjudicate.go resolves CONTESTED route×class verdicts (ADR 0030 Phase D). Two workers
// disagreed; the worldview honestly recorded Contested and refused to average; something must now
// decide, or every contested pair stays an unresolved asterisk on the engagement.
//
// THE DISPOSAL RULE (§10): a panel may only SELECT between the two evidenced sides — Vulnerable
// (its cited turns) or Clean (its cited attempts). It can never manufacture evidence, upgrade
// without turns, or touch non-contested entries (ResolveContested refuses all three). A tie or a
// wholly-failed panel KEEPS Contested: a deadlocked jury is not evidence of absence, and failing
// open here is exactly what it was in codesweep's panel.
//
// The jurors are LLM-personas (the internal/consensus pattern applied to a different question:
// codesweep judges PROPOSED candidates pre-grounding; this judges two GROUNDED sides post-merge).
// Every applied decision carries the vote + rationales into the ledger line, so a 2-1 and a
// unanimous are distinguishable in the audit trail.

// VerdictVote is one juror's answer.
type VerdictVote struct {
	Juror     string
	Verdict   Verdict // Vulnerable | Clean | "" when the juror declined/failed
	Rationale string
}

// Juror decides one contested case.
type Juror interface {
	Judge(ctx context.Context, c ClassVerdict) (VerdictVote, error)
}

// Adjudication is the recorded outcome for one contested pair.
type Adjudication struct {
	Route    string   `json:"route"`
	Class    string   `json:"class"`
	Resolved Verdict  `json:"resolved"` // Vulnerable | Clean | Contested (kept)
	Votes    []string `json:"votes"`    // "juror=vulnerable: rationale" lines (audit trail)
}

// PanelJuror scores one contested case with an LLM persona. The prompt hands the juror ONLY the
// cited turns of each side — no findings prose, no severity — so the vote is about EVIDENCE
// QUALITY, never about sympathy for a scary write-up.
type PanelJuror struct {
	Name string
	LLM  cloudengine.LLM
	Pose string // the persona framing ("skeptical of exploitation claims", …)
}

const adjudicatePromptTmpl = `You are %s on a security adjudication panel. Two automated probes disagreed about one endpoint.

Claimed class: %s
VULNERABLE side cites these executed request turns: [%s]
CLEAN side cites these executed attempt turns (payload fired, nothing triggered): [%s]

Rule: judge only whether each side's cited turns actually carry the evidence its claim needs. You cannot request new tests.
Reply with EXACTLY one JSON object, no prose:
{"verdict":"vulnerable"|"clean"|"abstain","rationale":"<one sentence>"}`

// Judge implements Juror. Any parse/refusal becomes an abstention — a malformed juror is one
// lost vote, never a forced resolution.
func (p PanelJuror) Judge(ctx context.Context, c ClassVerdict) (VerdictVote, error) {
	prompt := fmt.Sprintf(adjudicatePromptTmpl,
		p.Pose, c.Class,
		strings.Join(c.VulnEvidence, ", "), strings.Join(c.CleanEvidence, ", "))
	raw, err := p.LLM.Generate(ctx, prompt)
	if err != nil {
		return VerdictVote{Juror: p.Name}, err
	}
	var parsed struct {
		Verdict   string `json:"verdict"`
		Rationale string `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(stripToJSON(raw)), &parsed); err != nil {
		return VerdictVote{Juror: p.Name}, fmt.Errorf("panelist %s: unparsable reply: %w", p.Name, err)
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Verdict)) {
	case "vulnerable":
		return VerdictVote{Juror: p.Name, Verdict: Vulnerable, Rationale: parsed.Rationale}, nil
	case "clean":
		return VerdictVote{Juror: p.Name, Verdict: Clean, Rationale: parsed.Rationale}, nil
	default: // abstain / anything else — a declined opinion is not a vote
		return VerdictVote{Juror: p.Name, Verdict: "", Rationale: parsed.Rationale}, nil
	}
}

// DefaultPanel is the odd three-persona panel: independent-minded framings so agreement means
// something, majority wins, ties fail open to Contested.
func DefaultPanel(llm cloudengine.LLM) []Juror {
	return []Juror{
		PanelJuror{Name: "skeptic", Pose: "a skeptic who defaults to doubting exploitation claims", LLM: llm},
		PanelJuror{Name: "pragmatist", Pose: "a pragmatic incident responder who cares only about reproducible evidence", LLM: llm},
		PanelJuror{Name: "auditor", Pose: "an auditor who demands the strictest reading of what a cited turn proves", LLM: llm},
	}
}

// AdjudicateContested runs the panel over every Contested entry in w and applies majority
// outcomes. Returns one Adjudication per contested pair (resolved OR kept), so the caller renders
// both. Never returns an error for a failed vote — failures keep Contested and are RECORDED;
// only a worldview-level refusal (should be impossible post-check) surfaces as error.
func AdjudicateContested(ctx context.Context, w *Worldview, jurors []Juror) ([]Adjudication, error) {
	var out []Adjudication
	for _, cv := range w.Verdicts() { // deterministic order
		if cv.Verdict != Contested {
			continue
		}
		adj := Adjudication{Route: cv.Route, Class: cv.Class, Resolved: Contested}
		tally := map[Verdict]int{}
		for _, j := range jurors {
			vote, err := j.Judge(ctx, cv)
			if err != nil {
				adj.Votes = append(adj.Votes, fmt.Sprintf("%s=abstain: %v", vote.Juror, err))
				continue
			}
			line := fmt.Sprintf("%s=%s", vote.Juror, orAbstain(vote.Verdict))
			if vote.Rationale != "" {
				line += ": " + truncateLine(vote.Rationale, 200)
			}
			adj.Votes = append(adj.Votes, line)
			tally[vote.Verdict]++
		}
		// Majority strictly > half the PANEL SIZE (not the responding votes): two abstentions must
		// not let one voice decide. Tie / sub-majority → keep Contested (fail open).
		need := len(jurors)/2 + 1
		switch {
		case tally[Vulnerable] >= need && tally[Vulnerable] > tally[Clean]:
			err := w.ResolveContested(cv.Route, cv.Class, Vulnerable, "panel "+majorityLine(tally))
			if err == nil {
				adj.Resolved = Vulnerable
			}
		case tally[Clean] >= need && tally[Clean] > tally[Vulnerable]:
			err := w.ResolveContested(cv.Route, cv.Class, Clean, "panel "+majorityLine(tally))
			if err == nil {
				adj.Resolved = Clean
			}
		}
		out = append(out, adj)
	}
	return out, nil
}

func orAbstain(v Verdict) string {
	if v == "" {
		return "abstain"
	}
	return string(v)
}

func majorityLine(tally map[Verdict]int) string {
	return fmt.Sprintf("majority vulnerable=%d clean=%d", tally[Vulnerable], tally[Clean])
}

func truncateLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// stripToJSON extracts the first {...} block from a reply that ignored the format instruction.
func stripToJSON(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j <= i {
		return s
	}
	return s[i : j+1]
}
