package codeagent

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// patch_iterative.go adds the propose→verify→REFINE loop to the code engineer — the long-horizon
// pattern the product already runs on the offense side (the ModeDeep iterative driver) and for fix
// verification (retest.Verify), now applied to the fix side.
//
// A single-shot ProposePatch produces ONE attempt and cannot recover when its first fix is
// incomplete — the classic case being a prototype-pollution patch that blocks `__proto__` but is
// still bypassed by `constructor`. One vector closed, the vulnerability open, and nothing to say so.
//
// GROUNDED (§10): the model widens the search across attempts, but a DETERMINISTIC verifier — not
// the model — decides "fixed". Refinement can therefore never manufacture a false success; more
// attempts can only raise the hit rate, never invent one. This is the same propose/dispose split as
// llmspec.go and detectionskill.
//
// OVERFIT-FREE (§14.2): the refine prompt carries only the verifier's REAL output (the exploit
// re-ran and still worked), never an instance-specific hint about the expected answer.

// VerifyOutcome is the verifier's disposition of one proposed patch.
type VerifyOutcome struct {
	Fixed    bool   // the verifier confirmed the exploit is closed AND the app still works
	Feedback string // when NOT fixed: the verifier's real output, threaded into the next attempt
}

// Verifier applies a proposed patch and re-tests the exploit — an execution oracle, a rebuild+replay,
// retest.Verify. The CALLER supplies it, which keeps codeagent I/O-free and, more importantly, means
// the model can never grade its own fix.
type Verifier func(ctx context.Context, p Patch) VerifyOutcome

// ProposePatchIterative runs up to maxAttempts (floored to 1) of propose→verify→refine. It returns
// the last proposed patch, the attempt count reached, and whether the verifier CONFIRMED a fix.
//
// A nil verifier degrades to a single ProposePatch-equivalent call (attempts=1, confirmed=false) —
// with nothing to dispose, claiming more would be asserting a fix nobody checked. A propose/parse
// error stops the loop and is returned rather than silently retried.
func ProposePatchIterative(ctx context.Context, llm LLM, f Finding, sources []SourceFile, verify Verifier, maxAttempts int) (Patch, int, bool, error) {
	if llm == nil {
		return Patch{}, 0, false, fmt.Errorf("codeagent: no LLM configured (the engineer's brain) — cannot propose a patch")
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var last Patch
	var feedback string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		prompt := buildPatchPrompt(f, sources)
		if attempt > 1 && feedback != "" {
			prompt = buildRefinePrompt(f, sources, feedback)
		}
		out, err := llm.Generate(ctx, prompt)
		if err != nil {
			return last, attempt, false, err
		}
		files, perr := ParsePatch(out)
		if perr != nil {
			return Patch{Raw: out}, attempt, false, perr
		}
		p := Patch{Files: keepSupplied(files, sources), Raw: out}
		last = p

		if verify == nil {
			return p, attempt, false, nil // nothing disposed → never claim confirmed
		}
		if vo := verify(ctx, p); vo.Fixed {
			return p, attempt, true, nil
		} else {
			feedback = vo.Feedback
		}
	}
	return last, maxAttempts, false, nil
}

// keepSupplied drops any rewrite of a file we did not supply — a fix must edit the app, not invent
// new files or escape the build context. Shared by ProposePatch and the iterative loop so the two
// can never diverge on what a patch is allowed to touch.
func keepSupplied(files []PatchedFile, sources []SourceFile) []PatchedFile {
	supplied := make(map[string]bool, len(sources))
	for _, s := range sources {
		supplied[s.Path] = true
	}
	kept := files[:0]
	for _, pf := range files {
		if supplied[pf.Path] {
			kept = append(kept, pf)
		}
	}
	return kept
}

// buildRefinePrompt tells the engineer its last patch failed and hands back the verifier's real
// output. It re-supplies the ORIGINAL source rather than the failed patch, so the model re-reasons
// about the root cause instead of tweaking a broken diff — and carries no instance-specific hint.
func buildRefinePrompt(f Finding, sources []SourceFile, feedback string) string {
	var b strings.Builder
	b.WriteString("You are an application security engineer. Your PREVIOUS patch did NOT close the vulnerability:\n")
	b.WriteString("a deterministic verifier re-ran the exploit and it STILL succeeded (or the patch broke the app).\n\n")
	fmt.Fprintf(&b, "VULNERABILITY\n- class: %s\n- endpoint: %s\n", f.Class, f.Endpoint)
	if strings.TrimSpace(f.Detail) != "" {
		fmt.Fprintf(&b, "- evidence: %s\n", strings.TrimSpace(f.Detail))
	}
	fmt.Fprintf(&b, "\nVERIFIER OUTPUT (why your last patch failed)\n%s\n", strings.TrimSpace(feedback))
	b.WriteString("\nYour last fix was INCOMPLETE — it likely closed one attack vector but not all of them, or it\n")
	b.WriteString("broke normal behaviour. Rethink the ROOT CAUSE and cover every equivalent vector.\n")
	b.WriteString("Output ONLY the corrected files, each the COMPLETE new content between markers:\n")
	b.WriteString("    === FILE: <relative/path> ===\n    <full new file content>\n    === END FILE ===\n\n")
	b.WriteString("SOURCE FILES (original)\n")

	ordered := append([]SourceFile(nil), sources...) // don't reorder the caller's slice
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	for _, s := range ordered {
		fmt.Fprintf(&b, "\n=== FILE: %s ===\n%s\n=== END FILE ===\n", s.Path, s.Content)
	}
	return b.String()
}
