package codesweep

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

// disprover.go is ADR 0032 D4 — the Cloudflare Validate stage, applied to the
// sweep's uncovered-class findings. Every sweep finding is a pattern_match lead:
// a model read code and claimed a weakness. For classes WITH a deterministic
// predicate that claim gets executed into verified; for classes WITHOUT one
// (deserialization, business logic, authz) it stayed unverified forever. The
// disprover adds a second opinion WITHOUT blurring the §10 bar, under three hard
// constraints (each pinned by test):
//
//   - DOWNGRADE-ONLY: its outputs are clean | abstain. It can never create or
//     upgrade a finding; abstain fails open (the finding stands).
//   - RAW-EVIDENCE INPUT: the prompt carries the file excerpt and the claimed
//     CWE class + locations — NEVER the finder's rationale or title. A judge fed
//     the finder's story just agrees confidently (DryRun's poisoned-judge rule).
//   - LEDGERED: every verdict rides back on the candidate so the trace artifact
//     can reconstruct who decided what.

// Disproval is one adversarial second opinion.
type Disproval struct {
	Verdict   string `json:"verdict"` // "clean" | "abstain"
	Rationale string `json:"rationale"`
}

// Disprove asks an independent brain whether the claimed CWE actually manifests
// at the cited locations in the excerpt. The prompt carries ONLY raw evidence —
// never the finder's rationale/title, which would poison the judge (§10 via
// DryRun). Parse failures and refusals surface as errors; the caller fails open.
func Disprove(ctx context.Context, llm LLM, c Candidate, excerpt string) (Disproval, error) {
	if llm == nil {
		return Disproval{}, fmt.Errorf("codesweep: disprover needs an LLM")
	}
	cweName := strings.TrimSpace(c.CWE)
	locs := strings.Join(c.Evidence, ", ")
	prompt := "You are an ADVERSARIAL REVIEWER. Another model claims this file contains a vulnerability of class " +
		cweName + " at these locations: [" + locs + "].\n\n" +
		"Your job is to try to DISPROVE that claim using only the code below. Check whether the cited lines " +
		"actually exhibit the claimed weakness pattern, whether attacker-controlled input can reach them, and " +
		"whether any guard makes the claim false.\n\n" +
		"FILE: " + c.Path + "\n```\n" + excerpt + "\n```\n\n" +
		"Reply with EXACTLY one JSON object:\n" +
		`{"verdict":"vulnerable|clean","rationale":"<one sentence citing specific code>"}`
	out, err := llm.Generate(ctx, prompt)
	if err != nil {
		return Disproval{}, err
	}
	cleaned := stripFencesJSON(out)
	var parsed struct {
		Verdict   string `json:"verdict"`
		Rationale string `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(cleaned), &parsed); err != nil {
		return Disproval{}, fmt.Errorf("codesweep: disprover reply unparsable: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Verdict)) {
	case "clean":
		return Disproval{Verdict: "clean", Rationale: parsed.Rationale}, nil
	case "vulnerable":
		return Disproval{Verdict: "abstain", Rationale: parsed.Rationale}, nil // agrees ≠ new information; recorded as abstain
	default:
		return Disproval{}, fmt.Errorf("codesweep: disprover verdict %q not understood", parsed.Verdict)
	}
}

// stripFencesJSON pulls the first {...} block out of a reply that ignored format instructions.
func stripFencesJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
	}
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j <= i {
		return s
	}
	return s[i : j+1]
}

// DisproverResult carries what the second pass decided, so callers can disclose
// downgrades instead of silently shrinking the finding list.
type DisproverResult struct {
	Examined   int
	Downgraded int
	Kept       int
	Errors     int
}

// ApplyDisprover runs the adversarial pass over every Vulnerable candidate whose
// file exists in repo, downgrading to non-vulnerable those the disprover marks
// clean. Fail-open everywhere: any error keeps the candidate. Downgrades are
// RECORDED on the candidate (Evidence gains a disprover note) rather than erased,
// so the audit trail shows both sides.
func ApplyDisprover(ctx context.Context, llm LLM, res *Result, repo codelocalize.Repo, maxExcerptLines int) DisproverResult {
	if llm == nil || res == nil {
		return DisproverResult{}
	}
	byPath := repo.Index()
	maxLines := maxExcerptLines
	if maxLines <= 0 {
		maxLines = 400
	}
	var out DisproverResult
	for i := range res.Candidates {
		c := &res.Candidates[i]
		if !c.Vulnerable {
			continue
		}
		f, ok := byPath[c.Path]
		if !ok {
			continue
		}
		excerpt := excerptOf(f.Content, c.SinkLines, maxLines)
		v, err := Disprove(ctx, llm, *c, excerpt)
		out.Examined++
		if err != nil {
			out.Errors++
			continue
		}
		if v.Verdict == "clean" && strings.TrimSpace(v.Rationale) != "" {
			c.Vulnerable = false
			c.Evidence = append(c.Evidence, "disprover-downgraded: "+v.Rationale)
			out.Downgraded++
			continue
		}
		out.Kept++
	}
	return out
}

// excerptOf returns up to maxLines lines centered on the first sink line (or the
// whole head when no sink hints exist) — same focused-excerpt discipline Sweep uses.
func excerptOf(content string, sinkLines []int, maxLines int) string {
	lines := strings.Split(content, "\n")
	if len(lines) <= maxLines {
		return content
	}
	start := 0
	if len(sinkLines) > 0 && sinkLines[0] > 0 && sinkLines[0] <= len(lines) {
		start = sinkLines[0] - 1 - maxLines/4
		if start < 0 {
			start = 0
		}
	}
	end := start + maxLines
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}
