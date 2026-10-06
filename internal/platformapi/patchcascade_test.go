package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/tool/patchverify"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// taggedPatchLLM writes a patch whose content names the model that wrote it, plus a regression test
// (unless noTest), so the verifier and the assertions can tell the draft's work from the code model's.
type taggedPatchLLM struct {
	tag    string
	noTest bool
	calls  int
}

func (p *taggedPatchLLM) Generate(_ context.Context, _ string) (string, error) {
	p.calls++
	switch p.calls {
	case 1:
		return "=== FILE: app/db.go ===\npackage app // " + p.tag + "\n=== END FILE ===\n", nil
	case 2:
		if p.noTest {
			return "", nil
		}
		return "=== FILE: app/db_test.go ===\npackage app\n// exercises app/db.go:42\nfunc TestNoSQLi(t *testing.T) { if got := query(\"' OR 1=1\"); got != want { t.Fatalf(\"injected: %v\", got) } }\n=== END FILE ===\n", nil
	}
	return "", nil
}
func (p *taggedPatchLLM) ModelName() string { return p.tag + "-model" }

// cascadeDeps wires a draft model on the tenant and a code model as the operator model. verdictFor
// decides, per patched content, what the customer's tests say.
func cascadeDeps(t *testing.T, draft, code *taggedPatchLLM, verifier bool, verdictFor func(string) string) (Deps, platform.Action, platform.Connection) {
	t.Helper()
	d, a, c := patchDeps(t, nil)
	d.AgentLLM = code
	if draft != nil {
		tn, _ := d.Store.GetTenant(context.Background(), "t1")
		tn.LLMRoles = map[platform.AgentRole]*platform.LLMConfig{
			platform.RoleCodeDraft: {Provider: "ollama", Model: "draft-model", BaseURL: "http://localhost:11434/v1"},
		}
		_ = d.Store.PutTenant(context.Background(), tn)
		restore := draftClientFor
		draftClientFor = func(string, string, string, string) (pentest.SpecLLM, bool) { return draft, true }
		t.Cleanup(func() { draftClientFor = restore })
	}
	if verifier {
		d.PatchVerifier = func(_ context.Context, _, _ string, files map[string]string, _ string) (patchverify.Verdict, error) {
			return patchverify.Verdict{Status: verdictFor(files["app/db.go"]), Reason: "test run", Runner: "go test"}, nil
		}
	}
	return d, a, c
}

func always(s string) func(string) string { return func(string) string { return s } }

// The point of the cascade: a draft the tests accept ships, and the code model is never called.
func TestCascade_VerifiedDraftShipsWithoutTheCodeModel(t *testing.T) {
	draft, code := &taggedPatchLLM{tag: "draft"}, &taggedPatchLLM{tag: "code"}
	d, a, c := cascadeDeps(t, draft, code, true, always(patchverify.Verified))
	files, note, err := d.PatchForAction(context.Background(), a, c, "gh-token")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files["app/db.go"], "// draft") || code.calls != 0 {
		t.Fatalf("a verified draft must ship and the code model must not be called: file=%q codeCalls=%d", files["app/db.go"], code.calls)
	}
	if !strings.Contains(note, "draft model (draft-model)") || !strings.Contains(note, "verified") {
		t.Errorf("the PR note must say the draft model wrote it and that it was verified: %q", note)
	}
	// The draft's calls are spend like any other, under their own label, so the saving is measurable.
	rows, _ := d.Store.ListAISpend(context.Background(), "t1")
	drafted := false
	for _, r := range rows {
		if r.Kind == "fix patch (draft)" {
			drafted = true
			// The draft's spend belongs to the fix it wrote, so it counts toward cost per proven fix.
			if r.ActionID != a.ID {
				t.Errorf("draft spend is not tied to the action it produced: %+v", r)
			}
		}
	}
	if !drafted {
		t.Errorf("the draft model's calls were not metered under their own label: %+v", rows)
	}
}

// A draft the tests reject escalates ONCE to the code model, and the note says why.
func TestCascade_RejectedDraftEscalatesOnce(t *testing.T) {
	draft, code := &taggedPatchLLM{tag: "draft"}, &taggedPatchLLM{tag: "code"}
	verdict := func(content string) string {
		if strings.Contains(content, "draft") {
			return patchverify.NotFixed
		}
		return patchverify.Verified
	}
	d, a, c := cascadeDeps(t, draft, code, true, verdict)
	files, note, err := d.PatchForAction(context.Background(), a, c, "gh-token")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files["app/db.go"], "// code") || code.calls == 0 {
		t.Fatalf("a rejected draft must escalate to the code model: %q", files["app/db.go"])
	}
	if !strings.Contains(note, "did not produce a verified fix") || !strings.Contains(note, "not_fixed") {
		t.Errorf("the note must say the draft was tried and why it was not used: %q", note)
	}
}

// A draft nothing could check is not trusted: no regression test means no verdict, so it escalates.
func TestCascade_UncheckedDraftIsNotTrusted(t *testing.T) {
	draft, code := &taggedPatchLLM{tag: "draft", noTest: true}, &taggedPatchLLM{tag: "code"}
	d, a, c := cascadeDeps(t, draft, code, true, always(patchverify.Verified))
	files, _, err := d.PatchForAction(context.Background(), a, c, "gh-token")
	if err != nil || !strings.Contains(files["app/db.go"], "// code") {
		t.Fatalf("an unchecked draft must not ship: %q err=%v", files["app/db.go"], err)
	}
}

// Without an execution check there is nothing to decide with, so the draft is never tried; and with no
// draft configured the code model works exactly as before.
func TestCascade_OnlyWhereTheTestsCanDecide(t *testing.T) {
	t.Run("no verifier", func(t *testing.T) {
		draft, code := &taggedPatchLLM{tag: "draft"}, &taggedPatchLLM{tag: "code"}
		d, a, c := cascadeDeps(t, draft, code, false, nil)
		files, note, _ := d.PatchForAction(context.Background(), a, c, "gh-token")
		if draft.calls != 0 || !strings.Contains(files["app/db.go"], "// code") || strings.Contains(note, "draft model") {
			t.Fatalf("with no verifier the draft must not run: draftCalls=%d file=%q", draft.calls, files["app/db.go"])
		}
	})
	t.Run("no draft role", func(t *testing.T) {
		code := &taggedPatchLLM{tag: "code"}
		d, a, c := cascadeDeps(t, nil, code, true, always(patchverify.Verified))
		files, note, _ := d.PatchForAction(context.Background(), a, c, "gh-token")
		if !strings.Contains(files["app/db.go"], "// code") || strings.Contains(note, "draft model") {
			t.Fatalf("no draft configured must behave as before: %q / %q", files["app/db.go"], note)
		}
	})
}

// The draft role never falls back to the default model: same model twice is paying twice for one answer.
func TestDraftLLM_HasNoFallback(t *testing.T) {
	tn := platform.Tenant{LLM: &platform.LLMConfig{Provider: "openai", Model: "frontier", KeyRef: "k"}}
	if tn.DraftLLM() != nil {
		t.Fatal("an unset draft role resolved to the default model")
	}
	if tn.LLMForRole(platform.RoleCodeDraft) == nil {
		t.Fatal("sanity: the generic resolver does fall back — which is why the cascade must not use it")
	}
}
