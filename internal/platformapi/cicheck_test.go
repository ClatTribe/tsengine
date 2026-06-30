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

// A high+ finding on a CHANGED line blocks the merge (the CI gate); the action exits non-zero on blocked.
func TestCIPRCheck_BlocksOnFindingOnChangedLine(t *testing.T) {
	d := Deps{Store: store.NewMemory()}
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
	d := Deps{Store: store.NewMemory()}
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
