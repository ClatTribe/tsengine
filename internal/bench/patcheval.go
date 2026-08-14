// Package bench — PatchEval adapter.
//
// PatchEval (github.com/bytedance/PatchEval, Apache-2.0) is a NEUTRAL benchmark: 230 verified
// real-world CVEs from 2015–2025 in Go, JavaScript and Python, where a repair passes only when their
// Docker harness runs `fix-run.sh` to a zero exit AND the vulnerability is no longer exploitable.
//
// It is the right benchmark for the AI Security Engineer's central claim for three reasons: the
// language mix is exactly this segment's stack, the oracle is EXECUTION rather than a model's opinion,
// and there are published baselines to sit beside (GPT-5.6-Sol 83.9%, DeepSeek-V4-Flash 80.4%).
//
// # We supply the agent. They supply the tasks AND the verdict.
//
// This file deliberately contains no scoring. `internal/bench/cvepatch.go` — which this supersedes —
// had to define its own oracle because no suitable neutral one existed; PatchEval removes that
// problem, so the only honest role left for our code is to turn an instance into a prompt and a
// proposed patch into their output format. Anything here that graded a result would put us back to
// marking our own homework.
//
// # The leakage guard is the load-bearing part
//
// Each instance carries `fix_func` and `patch_url` — THE ANSWER. PatchEval withholds them from its own
// prompts for the obvious reason. An adapter that passed them through would score beautifully and mean
// nothing, and it would fail silently: a leaked benchmark looks exactly like a capable agent.
//
// So the prompt-building path takes ONLY the fields an agent is entitled to (cve_description, repo,
// language, cwe), and PromptFields refuses to return anything if an answer field is non-empty in the
// struct it was handed... it cannot: the type it returns has no field to put them in. The guard is
// structural, and `LeakedInto` exists to prove the rendered text stays clean even if someone later
// adds a field.
package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PatchEvalInstance is one record of patcheval_verified.json, field-for-field.
//
// The answer fields are parsed rather than dropped so a run can ASSERT they never reached the model —
// you cannot check for a leak of something you refused to read.
type PatchEvalInstance struct {
	CVEID          string `json:"cve_id"`
	CVEDescription string `json:"cve_description"`
	CWEInfo        string `json:"cwe_info"`
	Repo           string `json:"repo"`
	Language       string `json:"programing_language"` // their spelling
	ImageURL       string `json:"image_url"`

	// ── ANSWER FIELDS — never to be rendered into a prompt ──────────────────────────────────────
	PatchURL string `json:"patch_url"`
	FixFunc  string `json:"fix_func"`
	VulFunc  string `json:"vul_func"`
}

// PatchEvalPrompt is the subset of an instance an agent is entitled to see.
//
// It is a distinct type, not a filtered map, so the compiler enforces the boundary: there is nowhere
// to put the answer even by accident.
type PatchEvalPrompt struct {
	CVEID       string
	Description string
	CWE         string
	Repo        string
	Language    string
}

// PromptFields extracts what the agent may see. The answer fields are structurally unrepresentable in
// the result.
func PromptFields(in PatchEvalInstance) PatchEvalPrompt {
	return PatchEvalPrompt{
		CVEID:       strings.TrimSpace(in.CVEID),
		Description: strings.TrimSpace(in.CVEDescription),
		CWE:         strings.TrimSpace(in.CWEInfo),
		Repo:        strings.TrimSpace(in.Repo),
		Language:    strings.TrimSpace(in.Language),
	}
}

// LeakedInto reports which answer fields appear in text that is about to be sent to a model.
//
// PromptFields already makes a leak structurally impossible, so this is the second lock: prompts get
// assembled from several sources (finding, source files, retry context) and a future change could
// splice in a diff or a fixed function from somewhere else. A benchmark that has been leaked looks
// identical to a benchmark that has been passed, which is exactly why this must be checked mechanically
// rather than reasoned about.
//
// Short fragments are ignored: a fix_func of "get" would match everything and make the guard useless
// by crying wolf.
func LeakedInto(text string, in PatchEvalInstance) []string {
	var leaked []string
	check := func(name, val string) {
		v := strings.TrimSpace(val)
		if len(v) < 12 { // too short to be a meaningful, distinctive leak
			return
		}
		if strings.Contains(text, v) {
			leaked = append(leaked, name)
		}
	}
	check("patch_url", in.PatchURL)
	check("fix_func", in.FixFunc)
	sort.Strings(leaked)
	return leaked
}

// LoadPatchEval reads patcheval_verified.json. The dataset is NOT vendored — it is a third party's,
// it is large, and a copy in our tree would drift from theirs and quietly stop being their benchmark.
func LoadPatchEval(path string) ([]PatchEvalInstance, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("patcheval: read %s: %w", path, err)
	}
	var xs []PatchEvalInstance
	if err := json.Unmarshal(b, &xs); err != nil {
		return nil, fmt.Errorf("patcheval: parse %s: %w", path, err)
	}
	for i, x := range xs {
		if strings.TrimSpace(x.CVEID) == "" {
			return nil, fmt.Errorf("patcheval: instance %d has no cve_id", i)
		}
	}
	return xs, nil
}

// PatchEvalSubmission is exactly the record their evaluator reads.
type PatchEvalSubmission struct {
	CVE      string `json:"cve"`
	FixPatch string `json:"fix_patch"` // unified diff
}

// WriteSubmission writes one submission into the patches directory their evaluator mounts, one file
// per CVE as their harness expects.
//
// An EMPTY diff is written rather than skipped. A missing file and a patch that fixed nothing are
// different outcomes, and only one of them is honest about what the agent did — silently omitting the
// cases we failed on would inflate the denominator's disappearance into a better-looking score.
func WriteSubmission(dir string, s PatchEvalSubmission) error {
	if strings.TrimSpace(s.CVE) == "" {
		return fmt.Errorf("patcheval: submission has no cve id")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("patcheval: mkdir %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	name := filepath.Join(dir, safeCVEName(s.CVE)+".json")
	// 0600: a submission is written by this process and read by the evaluator running as the same
	// user, so nothing needs group or world read (gosec G306).
	if err := os.WriteFile(name, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("patcheval: write %s: %w", name, err)
	}
	return nil
}

// safeCVEName keeps a CVE id usable as a filename. Their ids are well-formed, but this adapter writes
// to disk from data we did not author.
func safeCVEName(cve string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(cve) {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
