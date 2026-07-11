package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/codeagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// cyberseceval.go runs our AI CODE Engineer (codeagent) against the REAL CyberSecEval dataset
// (Meta PurpleLlama, arXiv:2312.04724) — a shared PUBLIC benchmark, not self-made cases. The
// instruct set is 1916 expert-labeled INSECURE code snippets across 8 languages / 50 CWEs. We
// use it as a DETECTION test: give codeagent each snippet as a finding-to-verify and measure
// whether it confirms the real vulnerability — recall vs CyberSecEval's own Insecure-Code
// Detector (ICD: 96% precision / 79% recall).
//
// HONESTY (§10) + NO OVERFITTING (explicit): codeagent runs AS-IS — nothing is tuned to these
// samples. The dataset is operator-fetched (--dataset <path>), NOT committed (it's Meta's, and
// disk-heavy). This is DETECTION recall only — the set is all-positive (no secure negatives),
// so precision needs a separate labeled-negative set. A representative subset runs via the dev
// proxy for a real number; the full 1916-case run needs an autonomous LLM key.

// CSECase is one CyberSecEval instruct record (the fields we use).
type CSECase struct {
	PromptID    int    `json:"prompt_id"`
	FilePath    string `json:"file_path"`
	PatternDesc string `json:"pattern_desc"`
	CWE         string `json:"cwe_identifier"`
	Analyzer    string `json:"analyzer"`
	LineText    string `json:"line_text"`
	OriginCode  string `json:"origin_code"`
	Language    string `json:"language"`
}

// LoadCSE loads the real dataset. n<=0 → all; n>0 → a representative subset spread EVENLY across
// languages (so a small run isn't biased to one language), deterministic (stable order, no RNG).
func LoadCSE(path string, n int) ([]CSECase, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-provided dataset path
	if err != nil {
		return nil, err
	}
	var all []CSECase
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, fmt.Errorf("parse cyberseceval: %w", err)
	}
	if n <= 0 || n >= len(all) {
		return all, nil
	}
	// group by language, then round-robin take until n — even coverage, deterministic.
	byLang := map[string][]CSECase{}
	var langs []string
	for _, c := range all {
		if _, ok := byLang[c.Language]; !ok {
			langs = append(langs, c.Language)
		}
		byLang[c.Language] = append(byLang[c.Language], c)
	}
	sort.Strings(langs)
	var out []CSECase
	for i := 0; len(out) < n; i++ {
		progressed := false
		for _, lg := range langs {
			if i < len(byLang[lg]) {
				out = append(out, byLang[lg][i])
				progressed = true
				if len(out) == n {
					break
				}
			}
		}
		if !progressed {
			break
		}
	}
	return out, nil
}

// CSEResult is our codeagent's detection scorecard on CyberSecEval.
type CSEResult struct {
	Total      int             `json:"total"`
	Detected   int             `json:"detected"`
	Missed     []string        `json:"missed,omitempty"` // promptID:cwe codeagent did NOT confirm insecure
	ByLanguage map[string]lang `json:"by_language"`
}

type lang struct {
	Total    int `json:"total"`
	Detected int `json:"detected"`
}

// Recall is detected/total vs the ICD's published 79%.
func (r CSEResult) Recall() float64 {
	if r.Total == 0 {
		return 0
	}
	return float64(r.Detected) / float64(r.Total)
}

// RunCSEBench runs codeagent as a detector over each case and scores recall. llm is the code
// agent's brain (the dev proxy = frontier Claude, or a local Ollama). Runs sequentially.
func RunCSEBench(ctx context.Context, cases []CSECase, llm cloudengine.LLM) CSEResult {
	r := CSEResult{Total: len(cases), ByLanguage: map[string]lang{}}
	for _, c := range cases {
		lg := r.ByLanguage[c.Language]
		lg.Total++
		if detectCSE(ctx, c, llm) {
			r.Detected++
			lg.Detected++
		} else {
			r.Missed = append(r.Missed, fmt.Sprintf("%d:%s", c.PromptID, c.CWE))
		}
		r.ByLanguage[c.Language] = lg
	}
	return r
}

// detectCSE presents one CyberSecEval snippet to codeagent as a finding-to-verify and returns
// whether codeagent confirms it insecure/exploitable (the grounded detection).
func detectCSE(ctx context.Context, c CSECase, llm cloudengine.LLM) bool {
	line := snippetLine(c.OriginCode, c.LineText)
	fid := fmt.Sprintf("cse-%d", c.PromptID)
	finding := types.Finding{
		ID: fid, RuleID: "cyberseceval::" + c.CWE, Tool: firstNonEmptyCSE(c.Analyzer, "static"),
		Severity: types.SeverityHigh, Endpoint: fmt.Sprintf("%s:%d", c.FilePath, line),
		Title: c.PatternDesc, CWE: []string{c.CWE},
		Description: "A static analyzer flagged a possible " + c.CWE + " (" + c.PatternDesc + ") at this line. Confirm from source whether the weakness is really present.",
	}
	rep, err := codeagent.Investigate(ctx, llm,
		&codeagent.Context{Repo: "cyberseceval", Findings: []types.Finding{finding}, Source: codeagent.NewMapSource(map[string]string{c.FilePath: c.OriginCode})},
		codeagent.Options{MaxIters: 8})
	if err != nil || rep == nil {
		return false
	}
	for _, is := range rep.Issues {
		if is.FindingID == fid && is.Exploitable {
			return true
		}
	}
	return false
}

// snippetLine returns the 1-based line of lineText within code, else 1 (so read_source lands
// inside the snippet regardless of the dataset's absolute line number).
func snippetLine(code, lineText string) int {
	lt := strings.TrimSpace(lineText)
	if lt == "" {
		return 1
	}
	for i, ln := range strings.Split(code, "\n") {
		if strings.Contains(ln, lt) {
			return i + 1
		}
	}
	return 1
}

func firstNonEmptyCSE(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// RenderCSEMarkdown renders the CyberSecEval detection scorecard vs the ICD baseline.
func RenderCSEMarkdown(r CSEResult) string {
	var b strings.Builder
	b.WriteString("\n## CyberSecEval — codeagent detection recall on real insecure samples\n\n")
	b.WriteString("_Meta PurpleLlama (arXiv:2312.04724). codeagent as a DETECTOR over real labeled-insecure ")
	b.WriteString("snippets; recall vs the ICD's published 79%. Detection-only (all-positive set → no precision).__\n\n")
	fmt.Fprintf(&b, "- **detection recall %.0f%%** (%d/%d) · ICD baseline recall 79%%\n\n", r.Recall()*100, r.Detected, r.Total)
	if len(r.ByLanguage) > 0 {
		b.WriteString("| Language | Recall |\n|---|---|\n")
		langs := make([]string, 0, len(r.ByLanguage))
		for k := range r.ByLanguage {
			langs = append(langs, k)
		}
		sort.Strings(langs)
		for _, k := range langs {
			l := r.ByLanguage[k]
			rc := 0.0
			if l.Total > 0 {
				rc = float64(l.Detected) / float64(l.Total)
			}
			fmt.Fprintf(&b, "| %s | %.0f%% (%d/%d) |\n", k, rc*100, l.Detected, l.Total)
		}
	}
	if len(r.Missed) > 0 {
		fmt.Fprintf(&b, "\n- missed (codeagent did not confirm insecure): %v\n", r.Missed)
	}
	fmt.Fprintf(&b, "\n_Full 1916-case run needs an autonomous LLM key; this is a representative subset. Dataset operator-fetched, not committed._\n")
	return b.String()
}
