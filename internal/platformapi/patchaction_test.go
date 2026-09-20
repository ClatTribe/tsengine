package platformapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// patchLLM answers the patch prompt with a whole-file replacement in the engineer's marker format
// and the regression-test prompt with a test file; anything else gets nothing.
type patchLLM struct{ prompts []string }

func (p *patchLLM) Generate(_ context.Context, prompt string) (string, error) {
	p.prompts = append(p.prompts, prompt)
	switch len(p.prompts) {
	case 1: // the patch
		return "=== FILE: app/db.go ===\npackage app // parameterised query\n=== END FILE ===\n", nil
	case 2: // the regression test: must reference the patched file and carry an assertion to be kept
		return "=== FILE: app/db_test.go ===\npackage app\n// exercises app/db.go:42\nfunc TestNoSQLi(t *testing.T) { if got := query(\"' OR 1=1\"); got != want { t.Fatalf(\"injected: %v\", got) } }\n=== END FILE ===\n", nil
	}
	return "", nil
}

func patchDeps(t *testing.T, llm *patchLLM) (Deps, platform.Action, platform.Connection) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Plan: platform.PlanGrowth})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", RuleID: "semgrep::sqli", Tool: "semgrep", Severity: types.SeverityHigh,
		Title: "SQL injection", Endpoint: "app/db.go:42", CWE: []string{"CWE-89"}, Description: "string-built query"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/shop/contents/app/db.go" && r.Header.Get("Authorization") == "Bearer gh-token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"encoding":"base64","content":"` + base64.StdEncoding.EncodeToString([]byte("package app // vulnerable\n")) + `"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	d := Deps{Store: st, GitHubAPIBase: srv.URL}
	if llm != nil {
		d.AgentLLM = llm
	}
	a := platform.Action{ID: "a1", TenantID: "t1", FindingID: "f1", Kind: platform.ActOpenPR,
		Payload: map[string]any{"full_name": "acme/shop", "base": "main", "head": "tsengine/fix-f1"}}
	c := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Account: "acme"}
	return d, a, c
}

// The delivery-time patcher reads the cited file through the connection's token, gets whole-file
// replacements from the engineer, and returns them with the regression test riding along.
func TestPatchForAction_ReadsTheCitedFileAndReturnsThePatch(t *testing.T) {
	llm := &patchLLM{}
	d, a, c := patchDeps(t, llm)
	files, note, err := d.PatchForAction(context.Background(), a, c, "gh-token")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(files["app/db.go"]) != "package app // parameterised query" {
		t.Errorf("the patched file was not returned: %+v", files)
	}
	if files["app/db_test.go"] == "" || !strings.Contains(note, "regression test rides along") {
		t.Errorf("the regression test must ride along and be named in the note: files=%v note=%q", files, note)
	}
	if !strings.Contains(note, "codeagent.ProposePatch") {
		t.Errorf("the note must say which engine produced the patch: %q", note)
	}
	if len(llm.prompts) == 0 || !strings.Contains(llm.prompts[0], "package app // vulnerable") {
		t.Error("the engineer must be shown the file as read from the repository")
	}
}

// Refusals are errors the PR body quotes: no model, a location that is not a file, a missing finding.
func TestPatchForAction_RefusesWithAReasonRatherThanGuessing(t *testing.T) {
	d, a, c := patchDeps(t, nil) // no model
	if _, _, err := d.PatchForAction(context.Background(), a, c, "gh-token"); err == nil || !strings.Contains(err.Error(), "no AI model") {
		t.Errorf("no model must be a named refusal, got %v", err)
	}

	d, a, c = patchDeps(t, &patchLLM{})
	_ = d.Store.PutFinding(context.Background(), "t1", types.Finding{ID: "f2", RuleID: "nuclei::sqli", Title: "SQLi", Endpoint: "https://shop.acme.io/search?q="})
	a.FindingID = "f2"
	if _, _, err := d.PatchForAction(context.Background(), a, c, "gh-token"); err == nil || !strings.Contains(err.Error(), "not a repository file") {
		t.Errorf("a URL location must be refused as unpatchable, got %v", err)
	}

	a.FindingID = "missing"
	if _, _, err := d.PatchForAction(context.Background(), a, c, "gh-token"); err == nil || !strings.Contains(err.Error(), "no longer in the store") {
		t.Errorf("a vanished finding must be named, got %v", err)
	}
}
