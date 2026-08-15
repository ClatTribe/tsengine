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
)

func ciReq(body string) (*httptest.ResponseRecorder, *http.Request) {
	return httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/ci/pr-check", strings.NewReader(body))
}

// enabledPRBot returns Deps for a tenant that has EXPLICITLY turned the merge gate on.
//
// The blocking tests below are about CHANGED-LINE SCOPING, not about what an unconfigured tenant
// defaults to — they just never set a policy. That incidental setup was pinning the old default
// (nil policy → gate ON), which contradicted what /v1/settings/pr-bot showed the customer. The
// default now has its own tests; these get an explicit policy so they test what they claim to.
func enabledPRBot(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{
		ID: "ten-1", PRBot: &platform.PRBotPolicy{Enabled: true, BlockSeverity: "high"},
	}); err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st}
}

// A high+ finding on a CHANGED line blocks the merge (the CI gate); the action exits non-zero on blocked.
func TestCIPRCheck_BlocksOnFindingOnChangedLine(t *testing.T) {
	d := enabledPRBot(t)
	body := `{
		"changed_files": [{"path":"config.py","lines":[12]}],
		"findings": [{"id":"f-1","severity":"critical","title":"AWS key committed","endpoint":"config.py:12"}]
	}`
	rec, req := ciReq(body)
	d.handleCIPRCheck(rec, req, "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["blocked"] != true {
		t.Fatalf("a critical finding on a changed line should block, got %v", resp["blocked"])
	}
	if resp["conclusion"] != "failure" {
		t.Errorf("conclusion should be failure, got %v", resp["conclusion"])
	}
}

// The same finding NOT on a changed line does not block (the bot reviews what the PR touched).
func TestCIPRCheck_NoBlockWhenNotOnChangedLine(t *testing.T) {
	d := enabledPRBot(t)
	body := `{
		"changed_files": [{"path":"config.py","lines":[99]}],
		"findings": [{"id":"f-1","severity":"critical","title":"AWS key","endpoint":"config.py:12"}]
	}`
	rec, req := ciReq(body)
	d.handleCIPRCheck(rec, req, "ten-1")
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["blocked"] == true {
		t.Fatalf("a finding off the changed lines must not block, got %v", resp["blocked"])
	}
}

// A DISABLED pr-bot policy downgrades a would-be failure to neutral — informational, never gates.
func TestCIPRCheck_DisabledPolicyNeverBlocks(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{
		ID: "ten-1", PRBot: &platform.PRBotPolicy{Enabled: false, BlockSeverity: "high"},
	})
	d := Deps{Store: st}
	body := `{
		"changed_files": [{"path":"a.go","lines":[5]}],
		"findings": [{"id":"f-1","severity":"critical","title":"injection","endpoint":"a.go:5"}]
	}`
	rec, req := ciReq(body)
	d.handleCIPRCheck(rec, req, "ten-1")
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["blocked"] == true {
		t.Fatalf("a disabled policy must never block, got %v", resp["blocked"])
	}
	if resp["conclusion"] != "neutral" {
		t.Errorf("disabled policy should downgrade failure to neutral, got %v", resp["conclusion"])
	}
}

// ── SETTINGS AND THE GATE MUST AGREE ─────────────────────────────────────────────────────────────

// THE BUG. A workspace that had never touched the PR-bot setting read "enabled: false" in Settings
// while the CI gate treated it as ON and failed the check. Every new workspace was in that state, so
// installing the GitHub Action blocked merges on a policy the product said was off.
func TestPRBot_UnconfiguredTenantDoesNotBlockMerges(t *testing.T) {
	d := Deps{Store: store.NewMemory()}
	body := `{
		"changed_files": [{"path":"config.py","lines":[12]}],
		"findings": [{"id":"f-1","severity":"critical","title":"AWS key committed","endpoint":"config.py:12"}]
	}`
	rec, req := ciReq(body)
	d.handleCIPRCheck(rec, req, "ten-nopolicy")

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["blocked"] == true {
		t.Error("a tenant that never enabled the PR bot had its merge blocked — Settings shows this " +
			"workspace as disabled, so the gate must not fail their pipeline")
	}
	// It should still COMMENT: the check is informational until they turn it on.
	if cs, ok := resp["comments"].([]any); !ok || len(cs) == 0 {
		t.Error("the check stopped commenting entirely; it should still report, just not block")
	}
}

// The two surfaces must report the same thing for the same tenant. They previously each decided for
// themselves what an unconfigured tenant meant.
func TestPRBot_SettingsAndGateAgree(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		policy *platform.PRBotPolicy
		wantOn bool
	}{
		{name: "unconfigured", policy: nil, wantOn: false},
		{name: "explicitly off", policy: &platform.PRBotPolicy{Enabled: false, BlockSeverity: "high"}, wantOn: false},
		{name: "explicitly on", policy: &platform.PRBotPolicy{Enabled: true, BlockSeverity: "high"}, wantOn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := store.NewMemory()
			if err := st.PutTenant(ctx, platform.Tenant{ID: "ten-x", PRBot: tc.policy}); err != nil {
				t.Fatal(err)
			}
			d := Deps{Store: st}

			// What the gate does.
			rec, req := ciReq(`{"changed_files":[{"path":"a.py","lines":[1]}],
				"findings":[{"id":"f","severity":"critical","title":"x","endpoint":"a.py:1"}]}`)
			d.handleCIPRCheck(rec, req, "ten-x")
			var gate map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &gate)

			// What Settings shows.
			srec := httptest.NewRecorder()
			sreq := httptest.NewRequest(http.MethodGet, "/v1/settings/pr-bot", nil)
			d.handleGetPRBotSettings(srec, sreq, "ten-x")
			var shown map[string]any
			_ = json.Unmarshal(srec.Body.Bytes(), &shown)

			if shown["enabled"] != tc.wantOn {
				t.Errorf("Settings shows enabled=%v, want %v", shown["enabled"], tc.wantOn)
			}
			if blocked, _ := gate["blocked"].(bool); blocked != tc.wantOn {
				t.Errorf("the gate blocked=%v while Settings shows enabled=%v — a customer cannot "+
					"predict their own pipeline from the product's own settings page",
					blocked, shown["enabled"])
			}
		})
	}
}
