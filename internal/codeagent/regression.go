package codeagent

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// regression.go ships the TEST alongside the fix.
//
// WHY. A fix without a test is a fix that silently regresses. Someone refactors the sanitizer six months
// later, the vulnerability comes back, and nothing says so until it is found again from the outside —
// which is the same discovery path as the first time and costs the same. The competitive read that
// prompted this (tridentsecurity.io/solutions/web-app) puts it plainly: they deliver "a draft PR with
// the regression test" per confirmed finding. We delivered the fix.
//
// THE DANGER IS SPECIFIC, AND IT IS NOT "THE TEST IS WRONG". A test that passes trivially — asserts
// something unrelated, or asserts nothing — is WORSE than shipping no test at all. It goes green
// forever, and it tells every future reader that this vulnerability is covered. False assurance about a
// closed vulnerability is exactly the class of thing this codebase refuses everywhere else.
//
// So the model PROPOSES and the framework DISPOSES (§10). We cannot execute a test inside a customer's
// repository — no runtime, no fixtures, no dependencies — so the check is structural and deliberately
// narrow: the test must actually be ABOUT this fix (it names the patched file or the vulnerable symbol)
// and it must actually ASSERT something. A proposal that fails either is dropped rather than shipped
// with a caveat, because a caveat on a green test is not read.
//
// WHAT WE DO NOT CLAIM. This test is UNVERIFIED. We did not run it, and the PR body must say so — the
// honest claim is "here is a test that should fail on the old code", not "here is proof". Anything
// stronger would be the false assurance the structural gate exists to prevent.

// RegressionTest is a proposed test file plus the honest framing that must travel with it.
type RegressionTest struct {
	// File is the test to add. Empty when nothing survivable was produced.
	File PatchedFile
	// Note is what a reviewer needs to know before trusting it — it always says the test is unrun.
	Note string
	// Raw is the model output, for the evidence trail.
	Raw string
}

// Empty reports whether a usable test was produced.
func (r RegressionTest) Empty() bool {
	return r.File.Path == "" || strings.TrimSpace(r.File.Content) == ""
}

// ProposeRegressionTest asks for a test that fails on the vulnerable code and passes on the fix.
//
// Returns an empty result rather than an error when the proposal cannot be grounded — a missing test is
// a smaller problem than a fake one, and the caller ships the fix either way.
func ProposeRegressionTest(ctx context.Context, llm LLM, f Finding, fix Patch, sources []SourceFile) (RegressionTest, error) {
	if llm == nil {
		return RegressionTest{}, fmt.Errorf("codeagent: no LLM configured — cannot propose a regression test")
	}
	if fix.Empty() {
		// No fix means nothing to pin. Writing a test for a vulnerability still present would produce a
		// RED test in the customer's CI, which is a different (and unwelcome) deliverable.
		return RegressionTest{}, nil
	}
	out, err := llm.Generate(ctx, buildRegressionPrompt(f, fix, sources))
	if err != nil {
		return RegressionTest{}, err
	}
	files, perr := ParsePatch(out)
	if perr != nil || len(files) == 0 {
		return RegressionTest{Raw: out}, nil
	}

	// Take the first file that survives the gate. More than one test file for a single finding is
	// over-reach, not thoroughness.
	for _, cand := range files {
		if reason := rejectRegression(cand, f, fix); reason != "" {
			continue
		}
		return RegressionTest{
			File: cand,
			Raw:  out,
			Note: "This test was written by the engineer and HAS NOT BEEN RUN — we cannot execute your " +
				"suite. Run it against the pre-fix commit: it should FAIL there and pass here. If it " +
				"passes on both, it is not pinning this vulnerability and should be rewritten.",
		}, nil
	}
	return RegressionTest{Raw: out}, nil
}

// rejectRegression is the DISPOSE half: why this proposal must not ship, or "" to accept.
//
// Structural only, because we cannot run it. Both checks target the same failure — a test that is green
// forever and therefore lies about coverage.
func rejectRegression(cand PatchedFile, f Finding, fix Patch) string {
	body := cand.Content
	if strings.TrimSpace(body) == "" {
		return "empty"
	}
	// 1. It must be ABOUT this fix. A test that never mentions the patched file or the vulnerable
	//    location is testing something else, however plausible it looks.
	if !mentionsSubject(body, f, fix) {
		return "does not reference the patched file or the finding's location"
	}
	// 2. It must ASSERT. A test with no assertion runs, passes, and proves nothing — the exact shape of
	//    false assurance.
	if !hasAssertion(body) {
		return "contains no assertion"
	}
	return ""
}

// mentionsSubject reports whether the test refers to what was fixed — the patched file (by base name,
// since import paths differ from disk paths) or the finding's endpoint.
func mentionsSubject(body string, f Finding, fix Patch) bool {
	low := strings.ToLower(body)
	for _, pf := range fix.Files {
		base := strings.TrimSuffix(path.Base(pf.Path), path.Ext(pf.Path))
		if base != "" && strings.Contains(low, strings.ToLower(base)) {
			return true
		}
	}
	// The endpoint often carries the route or the file:line the scanner flagged.
	if ep := f.Endpoint; ep != "" {
		if i := strings.IndexAny(ep, ":?"); i > 0 {
			ep = ep[:i]
		}
		base := strings.TrimSuffix(path.Base(ep), path.Ext(ep))
		if len(base) > 2 && strings.Contains(low, strings.ToLower(base)) {
			return true
		}
	}
	return false
}

// hasAssertion looks for the assertion vocabulary of the languages this engine patches. Deliberately
// broad — a false NEGATIVE only costs a missing test, while a false POSITIVE ships a test that proves
// nothing, so the asymmetry is worth the crude list.
func hasAssertion(body string) bool {
	low := strings.ToLower(body)
	for _, tok := range []string{
		"assert", "expect(", "should", "t.error", "t.fatal", "require.", "chai", "pytest.raises",
		"tobe(", "toequal(", "tothrow(", "notequal", "must.",
	} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

func buildRegressionPrompt(f Finding, fix Patch, sources []SourceFile) string {
	var b strings.Builder
	b.WriteString("You are a security engineer who has just fixed a vulnerability. Write ONE test that " +
		"pins it closed.\n\n")
	b.WriteString("THE TEST MUST FAIL ON THE OLD CODE AND PASS ON THE NEW CODE. That is the entire point: a " +
		"test that passes on both is worse than no test, because it will go green forever and tell the " +
		"next engineer this vulnerability is covered when it is not.\n\n")

	fmt.Fprintf(&b, "VULNERABILITY\n  class: %s\n  location: %s\n", f.Class, f.Endpoint)
	if f.Detail != "" {
		fmt.Fprintf(&b, "  evidence: %s\n", f.Detail)
	}
	b.WriteString("\nTHE FIX THAT WAS APPLIED\n")
	for _, pf := range fix.Files {
		fmt.Fprintf(&b, "%s %s\n%s\n%s\n", patchBegin, pf.Path, pf.Content, patchEnd)
	}
	if len(sources) > 0 {
		b.WriteString("\nSURROUNDING SOURCE (for imports, helpers and test conventions)\n")
		for _, src := range sources {
			fmt.Fprintf(&b, "%s %s\n%s\n%s\n", patchBegin, src.Path, src.Content, patchEnd)
		}
	}
	b.WriteString("\nRULES\n")
	b.WriteString("- Exercise the ATTACK, not the happy path: feed the malicious input and assert it is " +
		"rejected, escaped, or otherwise made harmless.\n")
	b.WriteString("- Use the project's existing test framework and conventions, visible in the source above.\n")
	b.WriteString("- Reference the fixed file or function by name, so the test is obviously about this change.\n")
	b.WriteString("- One file. No commentary outside the code block.\n\n")
	b.WriteString("Return the complete test file in the SAME BLOCK FORMAT as a patch:\n")
	b.WriteString(patchBegin + " path/to/test_file\n<file contents>\n" + patchEnd + "\n")
	return b.String()
}
