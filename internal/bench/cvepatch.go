package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// cvepatch.go benchmarks the AI Security Engineer's CODE-FIX job — the actual product (an L2 agent
// that patches a real, confirmed app-sec vulnerability), NOT snippet-detection (CyberSecEval, wrong
// LAYER) and NOT native-C++ fuzzing-crash repair (SEC-bench, wrong DOMAIN — all 300 of its instances
// are C++ ASan bugs; our engineer does web/api/library app-sec: sqli/xss/idor/ssti/lfi/rce).
//
// It adopts SEC-bench's METHODOLOGY (real CVE + a GOLD PATCH as external ground truth + fix
// verification) but applies it to our domain and keeps it DISK-LIGHT: an instance is the vulnerable
// file(s) + the real fixing diff (a few KB), NOT SEC-bench's >200GB Docker rebuild oracle. Instances
// are operator-provided via --dataset (real CVEs with public fixing commits; NOT committed — external
// + disk-conscious, same honest gate as `tsbench cyberseceval`).
//
// The engine under test is codeagent.ProposePatch — "model PROPOSES, deterministic verifier DISPOSES"
// (§10). We score three GENERIC signals (no per-CVE logic — overfit-free, §14.2):
//   - produced:   the engineer returned an applicable file rewrite (else no_patch)
//   - localized:  the rewrite touches a file the GOLD patch also touched (necessary, not sufficient)
//   - fixed:      whether the rewrite CLOSES the vuln equivalently to gold — a JUDGED signal (execution
//                 oracle, or a frontier judge for a small proxy run). Never auto-set from the model's
//                 own claim (no LLM false positives). Carried as an input on the instance's result.
//
// The headline is the JUDGED fix-rate vs SEC-bench's published patch SOTA (34%) as METHODOLOGICAL
// context — same task shape, different domain, so it's a reference bar, not a head-to-head number.

// CVEPatchInstance is one real app-sec CVE the engineer must fix.
type CVEPatchInstance struct {
	ID        string      `json:"id"`               // e.g. "flask-CVE-2019-1010083"
	CVE       string      `json:"cve"`              // the real CVE id (external provenance)
	FixCommit string      `json:"fix_commit"`       // URL/sha of the real fixing commit (external provenance)
	Lang      string      `json:"lang"`             // js|ts|python|go|java|php|ruby …
	Class     string      `json:"class"`            // sqli|xss|idor|ssti|lfi|rce|… (codeagent.Finding.Class)
	Endpoint  string      `json:"endpoint"`         // the vulnerable route/location
	Detail    string      `json:"detail"`           // the confirmed-vuln rationale (grounds the fix; from the advisory)
	VulnFiles []VFile     `json:"vuln_files"`       // the offending file(s) at the pre-fix commit (the build context)
	GoldFiles []string    `json:"gold_files"`       // the file paths the REAL fixing commit modified (localization oracle)
	Verify    *VerifySpec `json:"verify,omitempty"` // optional execution oracle (real PoC + regression) → auto-scores `fixed`
}

// VFile is one source file the engineer may rewrite (pre-fix content).
type VFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// LoadCVEPatch reads an operator-provided instance set (JSON array). NOT committed — real CVE data,
// external + disk-conscious (same gate as the CyberSecEval dataset).
func LoadCVEPatch(path string) ([]CVEPatchInstance, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-provided dataset path
	if err != nil {
		return nil, err
	}
	var xs []CVEPatchInstance
	if err := json.Unmarshal(b, &xs); err != nil {
		return nil, fmt.Errorf("parse cvepatch dataset: %w", err)
	}
	return xs, nil
}

// CVEPatchResult is the per-instance scorecard.
type CVEPatchResult struct {
	ID        string          `json:"id"`
	CVE       string          `json:"cve"`
	Class     string          `json:"class"`
	Produced  bool            `json:"produced"`  // engineer returned an applicable rewrite
	Localized bool            `json:"localized"` // rewrite touches a gold-patched file
	Fixed     Judged          `json:"fixed"`     // JUDGED: does it close the vuln equivalently to gold
	OurFiles  []string        `json:"our_files"` // files the engineer rewrote (for the judge/evidence)
	Err       string          `json:"err,omitempty"`
	patch     codeagent.Patch // retained in-process for the judge; not serialized
}

// Judged is a tri-state so the harness never fabricates a fix verdict (no LLM false positives, §10):
// an un-judged run reports "unknown", not "fixed".
type Judged string

const (
	JudgeUnknown  Judged = "unknown" // no oracle/judge ran yet
	JudgeFixed    Judged = "fixed"   // an oracle (execution) or frontier judge confirmed equivalence
	JudgeNotFixed Judged = "not_fixed"
)

// Patch exposes the engineer's proposed rewrite so a judge (execution oracle or frontier proxy) can
// assess equivalence to gold. Kept off the JSON so the raw model output isn't dumped by default.
func (r CVEPatchResult) Patch() codeagent.Patch { return r.patch }

// RunCVEPatchBench runs the engineer's ProposePatch over each instance and scores the two AUTOMATIC
// signals (produced, localized). `fixed` stays JudgeUnknown until an external oracle/judge sets it —
// the harness never marks the engineer's own fix "working".
func RunCVEPatchBench(ctx context.Context, instances []CVEPatchInstance, llm codeagent.LLM) []CVEPatchResult {
	out := make([]CVEPatchResult, 0, len(instances))
	for _, in := range instances {
		r := CVEPatchResult{ID: in.ID, CVE: in.CVE, Class: in.Class, Fixed: JudgeUnknown}
		sources := make([]codeagent.SourceFile, 0, len(in.VulnFiles))
		for _, vf := range in.VulnFiles {
			sources = append(sources, codeagent.SourceFile{Path: vf.Path, Content: vf.Content})
		}
		p, err := codeagent.ProposePatch(ctx, llm,
			codeagent.Finding{Class: in.Class, Endpoint: in.Endpoint, Detail: in.Detail}, sources)
		if err != nil {
			r.Err = err.Error()
			out = append(out, r)
			continue
		}
		r.patch = p
		r.Produced = !p.Empty()
		gold := map[string]bool{}
		for _, g := range in.GoldFiles {
			gold[g] = true
		}
		for _, pf := range p.Files {
			r.OurFiles = append(r.OurFiles, pf.Path)
			if gold[pf.Path] {
				r.Localized = true
			}
		}
		// EXECUTION ORACLE disposes the fix verdict (never the model's own claim, §10). No spec/runtime
		// → stays JudgeUnknown (honest: no oracle, no verdict).
		if in.Verify != nil {
			r.Fixed = VerifyPatch(ctx, p, in.Verify)
		}
		out = append(out, r)
	}
	return out
}

// CVEPatchStats aggregates the run.
type CVEPatchStats struct {
	Total     int `json:"total"`
	Produced  int `json:"produced"`
	Localized int `json:"localized"`
	Fixed     int `json:"fixed"`  // JudgeFixed count (0 until a judge/oracle runs)
	Judged    int `json:"judged"` // instances with a non-unknown verdict
}

func ComputeCVEPatchStats(rs []CVEPatchResult) CVEPatchStats {
	s := CVEPatchStats{Total: len(rs)}
	for _, r := range rs {
		if r.Produced {
			s.Produced++
		}
		if r.Localized {
			s.Localized++
		}
		if r.Fixed != JudgeUnknown {
			s.Judged++
		}
		if r.Fixed == JudgeFixed {
			s.Fixed++
		}
	}
	return s
}

// RenderCVEPatchMarkdown renders the code-engineer patch scorecard.
func RenderCVEPatchMarkdown(rs []CVEPatchResult) string {
	s := ComputeCVEPatchStats(rs)
	var b strings.Builder
	b.WriteString("\n## AI Security Engineer — code-fix benchmark on real app-sec CVEs\n\n")
	b.WriteString("_SEC-bench METHODOLOGY (real CVE + gold patch + fix-verification) in OUR domain (web/api/")
	b.WriteString("library app-sec), disk-light. Engine: codeagent.ProposePatch (model proposes, verifier disposes, §10)._\n\n")
	fmt.Fprintf(&b, "- **produced a fix**: %d/%d · **localized to gold file**: %d/%d · **judged FIXED**: %d/%d judged\n",
		s.Produced, s.Total, s.Localized, s.Total, s.Fixed, s.Judged)
	b.WriteString("- SEC-bench published patch SOTA **34%** (native C++ domain) — a methodological reference bar, NOT a head-to-head number.\n")
	if s.Judged < s.Total {
		fmt.Fprintf(&b, "- ⚠️ %d/%d instances UN-judged (`fixed=unknown`): produced+localized are automatic; the fix verdict needs an execution oracle or a frontier judge — never the model's own claim (§10).\n", s.Total-s.Judged, s.Total)
	}
	b.WriteString("\n| Instance | CVE | Class | Produced | Localized | Fixed |\n|---|---|---|---|---|---|\n")
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	for _, r := range rs {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", r.ID, r.CVE, r.Class,
			yn(r.Produced), yn(r.Localized), string(r.Fixed))
	}
	return b.String()
}

func yn(b bool) string {
	if b {
		return "✓"
	}
	return "✗"
}
