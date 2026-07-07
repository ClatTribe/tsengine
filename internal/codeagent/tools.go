package codeagent

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// sourceCtx returns the investigation context (nil-safe — a zero Context / direct tool call uses Background).
func (cc *Context) sourceCtx() context.Context {
	if cc.ctx != nil {
		return cc.ctx
	}
	return context.Background()
}

// toolDef is one hand: the name + one-line help the brain sees, and the handler.
type toolDef struct {
	name    string
	help    string
	handler func(cc *Context, args map[string]any) string
}

// tools is the code specialist's small catalog (the "hands" over the source).
func tools() []toolDef {
	return []toolDef{
		{"list_findings", "list_findings() — the code findings under investigation: id, tool, severity, file:line, title", tListFindings},
		{"read_source", "read_source(path, line?, window?) — read source around a line (default ±12 lines; omit line for the file head). This is how you SEE the code, not just the finding text.", tReadSource},
		{"grep_code", "grep_code(pattern, max?) — search the repo for a symbol/sink/usage. Use it to TRACE: where a tainted value comes from, whether a sink is reachable, where a leaked secret is used (its blast radius).", tGrep},
		{"record_issue", "record_issue(finding_id, exploitable, severity, rationale, evidence[], blast_radius?, fix_location?, fix?) — commit your GROUNDED assessment. REJECTED unless evidence[] cites at least one real path:line you actually read.", tRecordIssue},
		{"finish", "finish(summary) — end the investigation and emit the executive summary", tFinish},
	}
}

func tListFindings(cc *Context, _ map[string]any) string {
	if len(cc.Findings) == 0 {
		return "no code findings in scope."
	}
	var b strings.Builder
	for _, f := range cc.Findings {
		loc := f.Endpoint
		if loc == "" {
			loc = "(no location)"
		}
		fmt.Fprintf(&b, "- id=%s | tool=%s | severity=%s | %s | %s\n", f.ID, f.Tool, f.Severity, loc, firstNonEmpty(f.Title, f.RuleID))
	}
	return strings.TrimRight(b.String(), "\n")
}

func tReadSource(cc *Context, args map[string]any) string {
	if cc.Source == nil {
		return "ERROR: no source access is wired for this run (the repo isn't connected). You cannot read code; assess only from the finding text or finish."
	}
	path := argStr(args, "path")
	if path == "" {
		return "ERROR: read_source needs a path. Use list_findings to see file locations, or grep_code to find one."
	}
	line := argInt(args, "line")
	window := argInt(args, "window")
	if window <= 0 {
		window = 12
	}
	start, end := 0, 0
	if line > 0 {
		start, end = line-window, line+window
		if start < 1 {
			start = 1
		}
	} else {
		start, end = 1, 2*window // file head
	}
	src, err := cc.Source.ReadFile(cc.sourceCtx(), path, start, end)
	if err != nil {
		return fmt.Sprintf("ERROR: cannot read %s: %v (check the path with grep_code / list_findings — do not cite source you can't read)", path, err)
	}
	if strings.TrimSpace(src) == "" {
		return fmt.Sprintf("%s has no lines in range %d-%d.", path, start, end)
	}
	return fmt.Sprintf("%s lines %d-%d:\n%s", path, start, end, src)
}

func tGrep(cc *Context, args map[string]any) string {
	if cc.Source == nil {
		return "ERROR: no source access is wired for this run."
	}
	pat := argStr(args, "pattern")
	if pat == "" {
		return "ERROR: grep_code needs a pattern."
	}
	max := argInt(args, "max")
	if max <= 0 || max > 40 {
		max = 20
	}
	hits, err := cc.Source.Grep(cc.sourceCtx(), pat, max)
	if err != nil {
		return "ERROR: grep failed: " + err.Error()
	}
	if len(hits) == 0 {
		return fmt.Sprintf("no matches for %q.", pat)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d match(es) for %q:\n", len(hits), pat)
	for _, h := range hits {
		fmt.Fprintf(&b, "- %s:%d  %s\n", h.Path, h.Line, strings.TrimSpace(h.Text))
	}
	return strings.TrimRight(b.String(), "\n")
}

// tRecordIssue commits a GROUNDED assessment. The grounding invariant (§10, the anti-hallucination guard):
// evidence[] must cite at least one path:line the SourceProvider can actually produce — so the agent cannot
// assert exploitability/blast-radius without having read the real code that backs it.
func tRecordIssue(cc *Context, args map[string]any) string {
	fid := argStr(args, "finding_id")
	if !cc.hasFinding(fid) {
		return fmt.Sprintf("REJECTED: finding_id %q is not in scope. Use list_findings.", fid)
	}
	evidence := argStrList(args, "evidence")
	grounded, reason := cc.evidenceGrounded(evidence)
	if !grounded {
		return "REJECTED (not grounded): " + reason + " — read the code with read_source/grep_code and cite a real path:line before recording."
	}
	cc.issueN++
	is := CodeIssue{
		ID:          fmt.Sprintf("code-%03d", cc.issueN),
		FindingID:   fid,
		Title:       argStr(args, "title"),
		Severity:    argStr(args, "severity"),
		Exploitable: argBool(args, "exploitable"),
		Rationale:   argStr(args, "rationale"),
		Evidence:    evidence,
		BlastRadius: argStr(args, "blast_radius"),
		FixLocation: argStr(args, "fix_location"),
		Fix:         argStr(args, "fix"),
	}
	if is.Title == "" {
		is.Title = titleOfFinding(cc.Findings, fid)
	}
	cc.Issues = append(cc.Issues, is)
	verdict := "NOT exploitable (grounded)"
	if is.Exploitable {
		verdict = "EXPLOITABLE (grounded in source you read)"
	}
	return fmt.Sprintf("recorded %s for %s: %s. Continue with another finding or finish.", is.ID, fid, verdict)
}

func tFinish(cc *Context, args map[string]any) string {
	cc.Summary = argStr(args, "summary")
	cc.Done = true
	return "code investigation closed."
}

// --- grounding helpers ---

func (cc *Context) hasFinding(id string) bool {
	for _, f := range cc.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

// evidenceGrounded requires at least one evidence entry ("path" or "path:line") that resolves to source the
// SourceProvider actually produces. Crucially it verifies the cited LINE exists, not merely the file: a
// citation like "handler.go:9999" on a 5-line file returns empty content (no line) and is REJECTED — so the
// §10 anti-hallucination guard can't be satisfied by pointing at a real file at a line the agent never read.
func (cc *Context) evidenceGrounded(evidence []string) (bool, string) {
	if len(evidence) == 0 {
		return false, "evidence[] is empty"
	}
	if cc.Source == nil {
		return false, "no source access — cannot verify any citation"
	}
	for _, e := range evidence {
		path, line := splitPathLine(e)
		if path == "" {
			continue
		}
		// line>0 → read EXACTLY that line (it must exist); line==0 (bare path) → the file must have content.
		start, end := line, line
		if line <= 0 {
			start, end = 1, 1
		}
		if src, err := cc.Source.ReadFile(cc.sourceCtx(), path, start, end); err == nil && strings.TrimSpace(src) != "" {
			return true, ""
		}
	}
	return false, "none of the cited locations point at real, readable source (the file:line must exist)"
}

// splitPathLine parses "path:line" (line optional) into its parts. A non-numeric or out-of-range suffix
// (including overflow) yields line 0 (treated as a bare path) rather than a corrupted value.
func splitPathLine(s string) (string, int) {
	s = strings.TrimSpace(s)
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return s, 0
	}
	n, err := strconv.Atoi(s[i+1:])
	if err != nil || n < 0 {
		return s, 0 // the part after ':' isn't a valid line number → whole thing is a path
	}
	return s[:i], n
}

func titleOfFinding(fs []types.Finding, id string) string {
	for _, f := range fs {
		if f.ID == id {
			return firstNonEmpty(f.Title, f.RuleID, id)
		}
	}
	return id
}

// --- arg + misc helpers ---

func argStr(args map[string]any, k string) string {
	if v, ok := args[k].(string); ok {
		return v
	}
	return ""
}

func argInt(args map[string]any, k string) int {
	switch v := args[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func argBool(args map[string]any, k string) bool {
	b, _ := args[k].(bool)
	return b
}

func argStrList(args map[string]any, k string) []string {
	raw, ok := args[k].([]any)
	if !ok {
		if s := argStr(args, k); s != "" {
			return []string{s}
		}
		return nil
	}
	var out []string
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// MapSource is an in-memory SourceProvider (path → file content). It backs tests today and any host-side
// caller that has already materialized the relevant files; the live connector-backed provider (GitHub
// file-contents / a stored scan checkout) implements the same interface. Deterministic + dependency-free.
type MapSource struct {
	files map[string]string
}

// NewMapSource builds a MapSource from a path→content map.
func NewMapSource(files map[string]string) *MapSource { return &MapSource{files: files} }

func (m *MapSource) ReadFile(_ context.Context, path string, startLine, endLine int) (string, error) {
	content, ok := m.files[path]
	if !ok {
		return "", fmt.Errorf("no such file")
	}
	lines := strings.Split(content, "\n")
	if startLine < 1 {
		startLine = 1
	}
	if endLine <= 0 || endLine > len(lines) {
		endLine = len(lines)
	}
	if startLine > len(lines) {
		return "", nil
	}
	var b strings.Builder
	for i := startLine; i <= endLine; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func (m *MapSource) Grep(_ context.Context, pattern string, maxHits int) ([]GrepHit, error) {
	var hits []GrepHit
	paths := make([]string, 0, len(m.files))
	for p := range m.files {
		paths = append(paths, p)
	}
	sort.Strings(paths) // deterministic order
	for _, p := range paths {
		for i, ln := range strings.Split(m.files[p], "\n") {
			if strings.Contains(ln, pattern) {
				hits = append(hits, GrepHit{Path: p, Line: i + 1, Text: ln})
				if len(hits) >= maxHits {
					return hits, nil
				}
			}
		}
	}
	return hits, nil
}

func (m *MapSource) Files() []string {
	out := make([]string, 0, len(m.files))
	for p := range m.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
