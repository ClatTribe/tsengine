package codeagent

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// patch_iterative.go adds the propose→verify→REFINE loop to the code engineer — the long-horizon
// pattern the product already uses on the offense side (the XBOW iterative driver) and for fix
// verification (retest.Verify), now on the fix side. A single-shot ProposePatch produces ONE
// attempt and cannot recover when its first fix is incomplete (closes one vector but not all — the
// classic prototype-pollution `__proto__`-only fix that a `constructor` payload still bypasses).
// ProposePatchIterative lets a DETERMINISTIC verifier dispose each attempt and, on failure, threads
// the verifier's reason into a refined next attempt.
//
// Grounded (§10): the model widens the search across attempts, but the verifier — not the model —
// decides "fixed", so refinement can NEVER manufacture a false success. Overfit-free (§14.2): the
// refine prompt carries only the verifier's real failure output (the exploit re-ran and still
// worked), never an instance-specific hint.

// VerifyOutcome is the verifier's disposition of one proposed patch.
type VerifyOutcome struct {
	Fixed    bool   // the deterministic verifier confirmed the exploit is closed AND the app still works
	Feedback string // when NOT fixed: the verifier's real output (why it still failed) — threaded into the next attempt
}

// Verifier applies a proposed patch and re-tests the exploit (an execution oracle, a rebuild+replay,
// retest.Verify). The caller supplies it, so codeagent stays I/O-free and the model can never grade
// its own fix.
type Verifier func(ctx context.Context, p Patch) VerifyOutcome

// ProposePatchIterative runs up to maxAttempts (floored 1) of propose→verify→refine. Returns the
// last proposed patch, the attempt count reached, and whether the verifier CONFIRMED a fix. With a
// nil verifier it degrades to a single ProposePatch call (attempts=1, confirmed=false — nothing to
// dispose). Any propose/parse error stops the loop and is returned.
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
			return p, attempt, false, nil
		}
		vo := verify(ctx, p)
		if vo.Fixed {
			return p, attempt, true, nil
		}
		feedback = vo.Feedback
	}
	return last, maxAttempts, false, nil
}

// keepSupplied drops any rewrite of a file we did not supply (a fix must edit the app, not invent
// new files or escape the build context) — shared by ProposePatch and the iterative loop.
func keepSupplied(files []PatchedFile, sources []SourceFile) []PatchedFile {
	supplied := map[string]bool{}
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

// buildRefinePrompt tells the engineer its last patch failed the verifier and hands back the
// verifier's real output. It carries the original source again (not the failed patch, so the model
// re-reasons rather than tweaks a broken diff) — and NO instance-specific hint (overfit-free).
func buildRefinePrompt(f Finding, sources []SourceFile, feedback string) string {
	var b strings.Builder
	b.WriteString("You are an application security engineer. Your PREVIOUS patch did NOT close the vulnerability:\n")
	b.WriteString("a deterministic verifier re-ran the exploit and it STILL succeeded (or it broke the app).\n\n")
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
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	for _, s := range sources {
		fmt.Fprintf(&b, "\n=== FILE: %s ===\n%s\n=== END FILE ===\n", s.Path, s.Content)
	}
	return b.String()
}
