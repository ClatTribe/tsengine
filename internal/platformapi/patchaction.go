package platformapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/codeagent"
	"github.com/ClatTribe/tsengine/internal/store"
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
	files := map[string]string{}
	for _, pf := range patch.Files {
		files[pf.Path] = pf.Content
	}
	note := "The patch is proposed by the AI engineer (codeagent.ProposePatch, the engine measured in tsbench cvepatch) from the file the finding cites."
	if reg, err := codeagent.ProposeRegressionTest(ctx, llm, cf, patch, sources); err == nil && !reg.Empty() {
		if _, clash := files[reg.File.Path]; !clash {
			files[reg.File.Path] = reg.File.Content
			note += " A regression test rides along in `" + reg.File.Path + "`; run it before and after to see the finding close."
		}
	} else {
		note += " No regression test could be written for it, so verification is your re-scan."
	}
	if d.Recorder != nil {
		d.Recorder.Record("patch attached to remediation PR", "l2-autofix",
			map[string]any{"tenant_id": a.TenantID, "action_id": a.ID, "finding_id": f.ID, "rule": f.RuleID,
				"repo": full, "files": len(files)},
			"the automated code-fix PR carries the engineer's diff, not only instructions")
	}
	return files, note, nil
}
