package platformapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/codeagent"
	"github.com/ClatTribe/tsengine/internal/fixcheck"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tool/patchverify"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// PatchForAction is the remediate.Patcher: at delivery time, turn a code-fix PR from instructions
// into a diff. It is the SAME engine the manual /v1/findings/{id}/autofix endpoint runs
// (codeagent.ProposePatch over the file the finding cites, read through the connection's token), so
// the automated pipeline and the button cannot produce different patches for the same finding.
//
// Refusals, each an error the PR body will quote rather than a silent instruction-only PR:
//   - no model configured for the tenant (Free tier without a key, or a key that does not resolve);
//   - the action cites no finding, or the finding is gone from the store;
//   - the finding's location is not a repository file path (a URL, an image layer, a package name);
//   - the file cannot be read at the PR's base branch;
//   - the engineer proposed no change, or a change to a file it was not shown (keepSupplied drops it).
//
// The regression test, when the engineer can write one, rides along as a second file: a patch with
// a test that fails before and passes after is the strongest evidence a PR can carry that the fix
// is real, and the reviewer is told when there is none.
func (d Deps) PatchForAction(ctx context.Context, a platform.Action, c platform.Connection, token string) (map[string]string, string, error) {
	llm := d.resolveAgentLLMForRole(ctx, a.TenantID, platform.RoleCode)
	if llm == nil {
		return nil, "", fmt.Errorf("no AI model is configured for this workspace, so the engineer could not write the patch (Settings → AI model)")
	}
	if a.FindingID == "" {
		return nil, "", fmt.Errorf("the action cites no finding to patch")
	}
	findings, err := d.Store.ListFindings(ctx, a.TenantID, store.FindingFilter{})
	if err != nil {
		return nil, "", err
	}
	var f *types.Finding
	for i := range findings {
		if findings[i].ID == a.FindingID {
			f = &findings[i]
			break
		}
	}
	if f == nil {
		return nil, "", fmt.Errorf("finding %s is no longer in the store", a.FindingID)
	}
	full, _ := a.Payload["full_name"].(string)
	owner, repo, ok := strings.Cut(full, "/")
	if !ok || owner == "" || repo == "" {
		return nil, "", fmt.Errorf("the action names no owner/repo to read from")
	}
	if strings.Contains(f.Endpoint, "://") || strings.HasPrefix(f.Endpoint, "/") || strings.TrimSpace(f.Endpoint) == "" {
		return nil, "", fmt.Errorf("the finding's location %q is not a repository file, so there is no file to patch", f.Endpoint)
	}
	path := f.Endpoint
	if i := strings.LastIndex(path, ":"); i > 0 {
		path = path[:i]
	}
	base, _ := a.Payload["base"].(string)
	src := codeagent.NewGitHubSource(owner, repo, base, token)
	if d.GitHubAPIBase != "" {
		src.Base = d.GitHubAPIBase
	}
	content, rerr := src.ReadFile(ctx, path, 0, 0)
	if rerr != nil || strings.TrimSpace(content) == "" {
		return nil, "", fmt.Errorf("could not read %s at %s to patch it: %v", path, nz(base, "the default branch"), rerr)
	}
	sources := []codeagent.SourceFile{{Path: path, Content: content}}
	cf := codeagent.Finding{Class: strings.ToLower(strings.Join(f.CWE, " ")), Endpoint: f.Endpoint, Detail: nz(f.Description, f.Title)}
	patch, perr := codeagent.ProposePatch(ctx, llm, cf, sources)
	if perr != nil {
		return nil, "", fmt.Errorf("the engineer could not produce a patch: %v", perr)
	}
	if patch.Empty() {
		return nil, "", nil
	}

	// PRE-DELIVERY SOUNDNESS GATE (host-side, always runs — no sandbox needed, unlike PatchVerifier
	// below). The patch is about to be committed to a PR branch a human is asked to merge; before it
	// is, check it is non-trivial, aimed at the cited line, and (for Go) still parses. A failing check
	// means the "fix" changes nothing, misses the vulnerable line, or breaks the build — none of which
	// should reach a reviewer as a diff. Withheld exactly like a patch the test suite rejects. This
	// proves soundness, NOT closure (the re-scan + re-attack verify closure post-deploy).
	// The file was read with line-number prefixes ("N: ...", the build-context format the engineer's
	// prompt needs); fixcheck compares against the CLEAN original, so strip them first — otherwise
	// every line differs and the checks are meaningless.
	cleanOriginal := stripLineNumbers(content)
	pairs := make([]fixcheck.File, 0, len(patch.Files))
	for _, pf := range patch.Files {
		pairs = append(pairs, fixcheck.File{Path: pf.Path, Original: cleanOriginal, Patched: pf.Content})
	}
	sound := fixcheck.Checks(fixcheck.Finding{Endpoint: f.Endpoint}, pairs)
	if sound.Blocking {
		return nil, "", fmt.Errorf("the engineer's patch failed a pre-delivery soundness check (%s); the diff is withheld and the instructions below stand",
			fixcheckFailures(sound))
	}

	files := map[string]string{}
	for _, pf := range patch.Files {
		files[pf.Path] = pf.Content
	}
	note := "The patch is proposed by the AI engineer (codeagent.ProposePatch, the engine measured in tsbench cvepatch) from the file the finding cites."
	note += " Pre-delivery checks: " + fixcheckSummary(sound) + "."
	regressionPath := ""
	if reg, err := codeagent.ProposeRegressionTest(ctx, llm, cf, patch, sources); err == nil && !reg.Empty() {
		if _, clash := files[reg.File.Path]; !clash {
			files[reg.File.Path] = reg.File.Content
			regressionPath = reg.File.Path
			note += " A regression test rides along in `" + reg.File.Path + "`."
		}
	} else {
		note += " No regression test could be written for it."
	}

	// EXECUTION VERIFICATION, when the deployment can run it. The verdict is stated in the PR body
	// either way, and a patch the customer's own tests reject is NOT attached: a PR carrying a diff
	// that breaks the suite, or one whose regression test still fails, is the "AI fix" that costs a
	// reviewer more than no patch. Unverifiable is not a failure — it is said as itself.
	switch {
	case d.PatchVerifier == nil:
		note += " It was NOT executed against your tests (this deployment has no sandbox verifier); your re-scan is the verification."
	case regressionPath == "":
		note += " It was NOT executed against your tests: without a regression test nothing can fail before and pass after."
	default:
		v, verr := d.PatchVerifier(ctx, a.TenantID, full, files, regressionPath)
		switch {
		case verr != nil:
			note += " It was NOT executed against your tests: " + verr.Error() + "."
		case v.Status == patchverify.Verified:
			note += " EXECUTED against your repository in the scan sandbox: " + v.Reason + " (runner: " + v.Runner + ")."
		case v.Status == patchverify.Unverifiable:
			note += " It could NOT be executed against your tests: " + v.Reason + "."
		default:
			// not_fixed / broke_suite / vacuous — the tests said no, so the diff does not ship.
			return nil, "", fmt.Errorf("the patch was executed against your repository's tests and rejected (%s: %s); the engineer's diff is withheld and the instructions below stand", v.Status, v.Reason)
		}
	}
	if d.Recorder != nil {
		d.Recorder.Record("patch attached to remediation PR", "l2-autofix",
			map[string]any{"tenant_id": a.TenantID, "action_id": a.ID, "finding_id": f.ID, "rule": f.RuleID,
				"repo": full, "files": len(files)},
			"the automated code-fix PR carries the engineer's diff, not only instructions")
	}
	return files, note, nil
}

// fixcheckFailures lists the checks that failed, for the withholding error.
func fixcheckFailures(r fixcheck.Report) string {
	var parts []string
	for _, c := range r.Checks {
		if c.Status == fixcheck.Fail {
			parts = append(parts, c.Message)
		}
	}
	return strings.Join(parts, "; ")
}

// fixcheckSummary renders every check's outcome for the PR body, so a reviewer sees what was and was
// not verified — a NotChecked is stated as itself, never dropped to look like a pass.
func fixcheckSummary(r fixcheck.Report) string {
	var parts []string
	for _, c := range r.Checks {
		parts = append(parts, string(c.Status)+" "+c.Name)
	}
	return strings.Join(parts, ", ")
}

// stripLineNumbers removes the "N: " prefix codeagent's ReadFile adds to each line for the model's
// build context, recovering the file's real content for fixcheck's comparison.
func stripLineNumbers(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		j := 0
		for j < len(ln) && ln[j] >= '0' && ln[j] <= '9' {
			j++
		}
		if j > 0 && j+1 < len(ln) && ln[j] == ':' && ln[j+1] == ' ' {
			lines[i] = ln[j+2:]
		} else if j > 0 && j+1 == len(ln) && ln[j] == ':' {
			lines[i] = "" // a numbered blank line ("2:")
		}
	}
	return strings.Join(lines, "\n")
}
