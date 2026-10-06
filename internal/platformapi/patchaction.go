package platformapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/codeagent"
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
	llm := d.resolveAgentLLMForRole(aiKind(ctx, "fix patch", "code"), a.TenantID, platform.RoleCode)
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
	// THE CASCADE. A cheaper draft model writes the fix first ONLY where the customer's own tests can
	// decide whether it worked; anything short of an executed, passing verdict escalates once to the code
	// model, which then behaves exactly as it always has. A patcher has no "nothing to fix" answer, so
	// escalating on failure cannot send true negatives to the expensive model — the failure mode that makes
	// cascades costlier than frontier-only on detection stages does not exist here.
	var draftNote string
	if d.PatchVerifier != nil {
		if draft := d.resolveDraftLLM(aiKind(ctx, "fix patch (draft)", "code"), a.TenantID); draft != nil {
			res := d.attemptPatch(ctx, draft, a, f, full, cf, sources)
			if res.outcome == patchVerified {
				return res.files, "Drafted by the workspace's draft model (" + modelName(draft) + ") and verified, so the code model was not needed. " + res.note, nil
			}
			draftNote = "The draft model (" + modelName(draft) + ") was tried first and did not produce a verified fix (" + res.why + "), so the code model wrote this one. "
		}
	}
	res := d.attemptPatch(ctx, llm, a, f, full, cf, sources)
	switch res.outcome {
	case patchNone:
		return nil, "", nil
	case patchFailed, patchRejected:
		return nil, "", res.err
	}
	return res.files, draftNote + res.note, nil
}

type patchOutcome int

const (
	patchNone       patchOutcome = iota // the engineer proposed no change
	patchFailed                         // the engineer could not produce a patch
	patchRejected                       // the customer's tests ran and said no
	patchUnverified                     // a patch, but nothing executed it
	patchVerified                       // a patch the customer's tests executed and accepted
)

type patchAttempt struct {
	outcome patchOutcome
	files   map[string]string
	note    string
	why     string // a short reason, for a draft that did not make it
	err     error
}

// attemptPatch is one model's try: propose, add a regression test, and execute both when the deployment
// can. It is the whole of the old single-model path, so the code model's behaviour is unchanged.
func (d Deps) attemptPatch(ctx context.Context, llm codeagent.LLM, a platform.Action, f *types.Finding, full string, cf codeagent.Finding, sources []codeagent.SourceFile) patchAttempt {
	patch, perr := codeagent.ProposePatch(ctx, llm, cf, sources)
	if perr != nil {
		return patchAttempt{outcome: patchFailed, why: "it could not produce a patch",
			err: fmt.Errorf("the engineer could not produce a patch: %v", perr)}
	}
	if patch.Empty() {
		return patchAttempt{outcome: patchNone, why: "it proposed no change"}
	}
	files := map[string]string{}
	for _, pf := range patch.Files {
		files[pf.Path] = pf.Content
	}
	note := "The patch is proposed by the AI engineer (codeagent.ProposePatch, the engine measured in tsbench cvepatch) from the file the finding cites."
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
	out := patchUnverified
	why := "nothing executed it"
	switch {
	case d.PatchVerifier == nil:
		note += " It was NOT executed against your tests (this deployment has no sandbox verifier); your re-scan is the verification."
	case regressionPath == "":
		note += " It was NOT executed against your tests: without a regression test nothing can fail before and pass after."
		why = "it wrote no regression test, so nothing could check it"
	default:
		v, verr := d.PatchVerifier(ctx, a.TenantID, full, files, regressionPath)
		switch {
		case verr != nil:
			note += " It was NOT executed against your tests: " + verr.Error() + "."
			why = "it could not be executed: " + verr.Error()
		case v.Status == patchverify.Verified:
			note += " EXECUTED against your repository in the scan sandbox: " + v.Reason + " (runner: " + v.Runner + ")."
			out = patchVerified
		case v.Status == patchverify.Unverifiable:
			note += " It could NOT be executed against your tests: " + v.Reason + "."
			why = "it could not be executed: " + v.Reason
		default:
			// not_fixed / broke_suite / vacuous — the tests said no, so the diff does not ship.
			return patchAttempt{outcome: patchRejected, why: "your tests rejected it (" + string(v.Status) + ")",
				err: fmt.Errorf("the patch was executed against your repository's tests and rejected (%s: %s); the engineer's diff is withheld and the instructions below stand", v.Status, v.Reason)}
		}
	}
	if d.Recorder != nil {
		d.Recorder.Record("patch attached to remediation PR", "l2-autofix",
			map[string]any{"tenant_id": a.TenantID, "action_id": a.ID, "finding_id": f.ID, "rule": f.RuleID,
				"repo": full, "files": len(files), "model": modelName(llm)},
			"the automated code-fix PR carries the engineer's diff, not only instructions")
	}
	return patchAttempt{outcome: out, files: files, note: note, why: why}
}

// modelName reads the model id off a client that knows it, for the PR note and the ledger.
func modelName(llm any) string {
	if mn, ok := llm.(cloudengine.ModelNamer); ok && mn.ModelName() != "" {
		return mn.ModelName()
	}
	return "unnamed model"
}
