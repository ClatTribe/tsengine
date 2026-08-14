// Package codeagent is the first increment of the AI Security Engineer's CODE-depth capability (ADR 0013).
// The full design is a ReAct agent over a repo graph; this first slice is the single-shot PATCH proposer
// the XBOW defense benchmark (ADR 0014) needs: given a proven web vulnerability + the app source, ask the
// engineer's model to produce a fixed version of the offending file(s). The model PROPOSES; a deterministic
// verifier (rebuild + replay the recorded exploit + a regression guard) DISPOSES — so the engineer can
// never mark its own fix "working" (no LLM false positives, §10), exactly as the offensive agent proposes
// and a predicate disposes.
package codeagent

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// LLM is the minimal model seam — EXACTLY cloudengine.LLM's shape (a single Generate), so an
// OpenAI-compat client (the local proxy) or the customer's key satisfies it directly with no adapter.
// Kept tiny so codeagent stays testable with a scripted fake.
type LLM interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// Finding is the proven vulnerability the engineer must fix (class + where + why).
type Finding struct {
	Class    string // sqli | xss | ssti | lfi | idor | rce | ...
	Endpoint string // the vulnerable route/path
	Detail   string // the offensive evidence / rationale (grounds the fix)
}

// SourceFile is one file from the build context the engineer may rewrite.
type SourceFile struct {
	Path    string
	Content string
}

// PatchedFile is one file the engineer rewrote (whole-file replacement — robust to the whitespace/line-
// ending drift that breaks unified-diff application, and trivial to apply + verify).
type PatchedFile struct {
	Path    string
	Content string
}

// Patch is the engineer's proposed fix + provenance.
type Patch struct {
	Files []PatchedFile
	Raw   string // the raw model output (for the evidence trail)
}

// Empty reports whether the engineer produced no applicable file change (→ the run scores no_patch).
func (p Patch) Empty() bool { return len(p.Files) == 0 }

// ProposePatch asks the engineer's model to fix the vulnerability, returning whole-file replacements. The
// model only proposes; the caller rebuilds + re-attacks to dispose. Grounded (§10): the prompt carries the
// real finding + real source, and a fix that touches a path outside the supplied source is rejected at
// parse time. No LLM → the caller must not run this (there is nothing honest to return).
func ProposePatch(ctx context.Context, llm LLM, f Finding, sources []SourceFile) (Patch, error) {
	if llm == nil {
		return Patch{}, fmt.Errorf("codeagent: no LLM configured (the engineer's brain) — cannot propose a patch")
	}
	out, err := llm.Generate(ctx, buildPatchPrompt(f, sources))
	if err != nil {
		return Patch{}, err
	}
	files, perr := ParsePatch(out)
	if perr != nil {
		return Patch{Raw: out}, perr
	}
	// Only allow rewrites of files we actually supplied — a fix must edit the app, not invent new files or
	// escape the build context (defence-in-depth on top of the traversal check). Shared with the
	// iterative loop via keepSupplied so the two can never diverge on what a patch may touch.
	return Patch{Files: keepSupplied(files, sources), Raw: out}, nil
}

// buildPatchPrompt renders the instruction. It is deliberately GENERIC — no per-challenge hints, no payload
// strings — so scoring stays overfit-free: the engineer gets the class + endpoint + evidence + source, the
// same information a human AppSec engineer would, and must reason the fix itself.
func buildPatchPrompt(f Finding, sources []SourceFile) string {
	var b strings.Builder
	// FRAMING IS PART OF THE TASK, and this was overfit to one shape of it.
	//
	// It used to say "a penetration test PROVED a vulnerability in the WEB APPLICATION below" and to
	// demand that "the homepage still responds". That is exactly right for the offensive-agent case it
	// was written for, and wrong for the other half of the engineer's job: most real fixes are library
	// CVEs — a path traversal in an archive extractor, a prototype pollution in a merge helper — where
	// there is no pentest, no web app, and no homepage, and where correctness is judged by the
	// project's own test suite. Telling the model to protect a homepage that does not exist steers it
	// toward request-level patches for defects that live in a function.
	//
	// So the wording now describes what is true of BOTH shapes: a software component, whose existing
	// behaviour and tests must still pass. A web app has tests and normal behaviour too, so nothing is
	// lost on the case this was originally tuned for.
	b.WriteString("You are an application security engineer. A real, exploitable vulnerability has been\n")
	b.WriteString("identified in the software below. Produce a minimal source patch that CLOSES the\n")
	b.WriteString("vulnerability while preserving existing behaviour (do not disable or break features).\n\n")
	fmt.Fprintf(&b, "VULNERABILITY\n- class: %s\n- endpoint: %s\n", f.Class, f.Endpoint)
	if strings.TrimSpace(f.Detail) != "" {
		fmt.Fprintf(&b, "- evidence: %s\n", strings.TrimSpace(f.Detail))
	}
	b.WriteString("\nRULES\n")
	b.WriteString("- Fix the ROOT CAUSE (e.g. parameterise the query, encode output, validate the path/identifier,\n")
	b.WriteString("  enforce authorization) — do NOT just block one payload or break the endpoint.\n")
	b.WriteString("- Keep it working: existing tests and normal behaviour must still pass. A patch that breaks\n")
	b.WriteString("  the build or the project's test suite is a failed patch, not a fix.\n")
	b.WriteString("- Output ONLY the files you changed, each as the COMPLETE new file content between markers:\n")
	b.WriteString("    === FILE: <relative/path> ===\n    <full new file content>\n    === END FILE ===\n")
	b.WriteString("- Change as few files as possible. If you cannot fix it safely, output nothing.\n\n")
	b.WriteString("SOURCE FILES\n")
	// Deterministic order so the same estate yields the same prompt (reproducible provenance).
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	for _, s := range sources {
		fmt.Fprintf(&b, "\n=== FILE: %s ===\n%s\n=== END FILE ===\n", s.Path, s.Content)
	}
	return b.String()
}

// --- patch format (the engineer's output → applied file replacements) ---

const (
	patchBegin = "=== FILE:"
	patchEnd   = "=== END FILE ==="
)

// ParsePatch extracts whole-file replacements from the engineer's response (the FILE-block format above).
// No blocks → (nil, nil): the engineer legitimately produced no patch (→ no_patch, never a fabricated fix).
// A malformed block (BEGIN with no END) or an unsafe path (traversal/absolute) is a hard error.
func ParsePatch(out string) ([]PatchedFile, error) {
	var files []PatchedFile
	rest := out
	for {
		bi := strings.Index(rest, patchBegin)
		if bi < 0 {
			break
		}
		after := rest[bi+len(patchBegin):]
		nl := strings.IndexByte(after, '\n')
		if nl < 0 {
			return nil, fmt.Errorf("patch: FILE marker with no newline")
		}
		path := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(after[:nl]), "==="))
		body := after[nl+1:]
		ei := strings.Index(body, patchEnd)
		if ei < 0 {
			return nil, fmt.Errorf("patch: FILE %q has no END marker", path)
		}
		if !safeRelPath(path) {
			return nil, fmt.Errorf("patch: unsafe path %q (traversal/absolute rejected)", path)
		}
		files = append(files, PatchedFile{Path: path, Content: strings.TrimRight(body[:ei], "\n")})
		rest = body[ei+len(patchEnd):]
	}
	return files, nil
}

// safeRelPath rejects absolute paths and `..` traversal so an applied patch can only write inside the build
// context (a patch must never escape to touch the host).
func safeRelPath(p string) bool {
	p = strings.TrimSpace(p)
	return p != "" && !strings.HasPrefix(p, "/") && !strings.Contains(p, "..")
}
