package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/asset/repository"
	"github.com/ClatTribe/tsengine/internal/sandbox"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/internal/tool/patchverify"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// patchVerifier execution-verifies a proposed patch in the scan sandbox: the repository the action
// names is cloned exactly as a scan clones it, mounted into a fresh sandbox, and the `patchverify`
// tool runs the repository's own suite and the engineer's regression test before and after the
// patch. The clone and the container live only for this call.
//
// It is the product's answer to a number that used to describe only the bench: "2/2 real CVEs
// fixed" was measured by an oracle no customer PR ever went through. Now a PR's body says whether
// the patch was executed against the customer's own tests, and a patch the tests reject is not
// attached at all.
func patchVerifier(images sandbox.ScanImages, st store.Store, vault secret.Vault) func(ctx context.Context, tenantID, fullName string, files map[string]string, regression string) (patchverify.Verdict, error) {
	spawn := sandboxDispatcherWS(images, st, vault)
	return func(ctx context.Context, tenantID, fullName string, files map[string]string, regression string) (patchverify.Verdict, error) {
		assets, err := st.ListAssets(ctx, tenantID)
		if err != nil {
			return patchverify.Verdict{}, err
		}
		var repo *platform.Asset
		for i := range assets {
			a := assets[i]
			if a.Type != "repository" {
				continue
			}
			if strings.EqualFold(a.Meta["full_name"], fullName) || strings.EqualFold(strings.TrimSuffix(strings.TrimPrefix(a.Target, "https://github.com/"), ".git"), fullName) {
				repo = &a
				break
			}
		}
		if repo == nil {
			return patchverify.Verdict{}, fmt.Errorf("no monitored repository asset matches %s, so there is no checkout to run the tests in", fullName)
		}
		disp, _, cleanup, err := spawn(ctx, *repo)
		if err != nil {
			return patchverify.Verdict{}, fmt.Errorf("could not stage the repository in a sandbox: %w", err)
		}
		defer cleanup()
		res, err := disp.Execute(ctx, "patchverify", tool.Args{
			"target": repository.WorkspacePath, "files": files, "regression": regression,
		})
		if err != nil {
			return patchverify.Verdict{}, fmt.Errorf("patchverify did not run: %w", err)
		}
		out, _ := res.Output.(string)
		var v patchverify.Verdict
		if err := json.Unmarshal([]byte(out), &v); err != nil || v.Status == "" {
			return patchverify.Verdict{}, fmt.Errorf("patchverify returned no verdict: %q", out)
		}
		return v, nil
	}
}
