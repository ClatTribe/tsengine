package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func verifyFixDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Plan: platform.PlanGrowth})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", RuleID: "semgrep::sqli", Tool: "semgrep",
		Severity: types.SeverityHigh, Title: "SQLi", Endpoint: "app/db.go:2", CWE: []string{"CWE-89"}})
	return Deps{Store: st}
}

func callVerifyFix(t *testing.T, d Deps, id, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest("POST", "/v1/findings/"+id+"/verify-fix", strings.NewReader(body))
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	d.handleVerifyFix(w, r, "t1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A no-op patch (original supplied, identical) is reported as blocking — and the handler never says "safe".
func TestVerifyFix_NoOpBlocks(t *testing.T) {
	d := verifyFixDeps(t)
	orig := "package app\nfunc q() { db(userInput) }\n"
	body, _ := json.Marshal(map[string]string{"original": orig, "patched": orig})
	code, out := callVerifyFix(t, d, "f1", string(body))
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	snd, _ := out["soundness"].(map[string]any)
	if snd["blocking"] != true {
		t.Errorf("a no-op patch must block, got %v", snd["blocking"])
	}
	// The scope note must never promise safety/closure.
	note, _ := snd["note"].(string)
	low := strings.ToLower(note)
	if strings.Contains(low, "safe") || strings.Contains(low, "closed") && !strings.Contains(low, "not that") {
		// the note is allowed to say "NOT that the vulnerability is closed"
		if !strings.Contains(low, "not") {
			t.Errorf("the note must not promise safety/closure: %q", note)
		}
	}
}

// A real fix that rewrites the cited line is not blocking.
func TestVerifyFix_RealFixPasses(t *testing.T) {
	d := verifyFixDeps(t)
	orig := "package app\nfunc q() { db(\"SELECT \"+id) }\n"
	patched := "package app\nfunc q() { db(\"SELECT ?\", id) }\n"
	body, _ := json.Marshal(map[string]string{"original": orig, "patched": patched})
	code, out := callVerifyFix(t, d, "f1", string(body))
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	snd, _ := out["soundness"].(map[string]any)
	if snd["blocking"] == true {
		t.Errorf("a sound fix must not block: %v", snd)
	}
}

// Missing patched content is a 400.
func TestVerifyFix_RequiresPatched(t *testing.T) {
	d := verifyFixDeps(t)
	code, _ := callVerifyFix(t, d, "f1", `{"original":"x"}`)
	if code != http.StatusBadRequest {
		t.Errorf("missing patched should be 400, got %d", code)
	}
}

// An unknown finding is a 404 — never a verdict against a finding that doesn't exist.
func TestVerifyFix_UnknownFinding(t *testing.T) {
	d := verifyFixDeps(t)
	code, _ := callVerifyFix(t, d, "nope", `{"patched":"package x\n"}`)
	if code != http.StatusNotFound {
		t.Errorf("unknown finding should be 404, got %d", code)
	}
}
