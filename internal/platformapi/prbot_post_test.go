package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

type fakeApp struct{ err error }

func (f fakeApp) InstallationToken(_ context.Context, id string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "ghs_" + id, nil
}

const prBody = `{
	"changed_files": [{"path":"config.py","lines":[12]}],
	"findings": [{"id":"f-1","severity":"critical","title":"AWS key committed","endpoint":"config.py:12"}],
	"repository": "acme/api", "pull_number": 7, "head_sha": "abc123"
}`

// The pr-check POSTS the check-run and the review when the App is configured and the workspace
// has recorded its installation id; every other state says why it did not, and the verdict is
// returned regardless so the exit-code gate keeps working.
func TestCIPRCheck_PostsWithTheAppAndNamesWhyNot(t *testing.T) {
	ctx := context.Background()
	var seen []string
	var auth []string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		auth = append(auth, r.Header.Get("Authorization"))
		if strings.Contains(r.URL.Path, "/repos/acme/broken/") {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer gh.Close()

	d := enabledPRBot(t)
	call := func(body string) map[string]any {
		rec, req := ciReq(body)
		d.handleCIPRCheck(rec, req, "ten-1")
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp
	}

	// 1. No App on the deployment: verdict computed, not posted, reason names the operator's step.
	resp := call(prBody)
	if resp["blocked"] != true || resp["posted"] != false || !strings.Contains(resp["not_posted_reason"].(string), "no GitHub App") {
		t.Errorf("unconfigured App: %v", resp)
	}
	// 2. App configured, no GitHub connection.
	d.GitHubApp = fakeApp{}
	d.GitHubAPIBase = gh.URL
	if resp := call(prBody); resp["posted"] != false || !strings.Contains(resp["not_posted_reason"].(string), "no GitHub connection") {
		t.Errorf("no connection: %v", resp)
	}
	// 3. Connected, but the App is not installed (no installation id recorded).
	_ = d.Store.PutConnection(ctx, platform.Connection{ID: "gh", TenantID: "ten-1", Kind: platform.ConnGitHub, Status: platform.ConnActive})
	if resp := call(prBody); resp["posted"] != false || !strings.Contains(resp["not_posted_reason"].(string), "installation id") {
		t.Errorf("no installation: %v", resp)
	}
	// 4. Installation recorded → posted with the installation token, check-run first.
	_ = d.Store.PutConnection(ctx, platform.Connection{ID: "gh", TenantID: "ten-1", Kind: platform.ConnGitHub, Status: platform.ConnActive,
		Config: map[string]string{GitHubInstallationKey: "777"}})
	resp = call(prBody)
	if resp["posted"] != true || resp["not_posted_reason"] != "" {
		t.Fatalf("installed: %v", resp)
	}
	if len(seen) != 2 || seen[0] != "POST /repos/acme/api/check-runs" || seen[1] != "POST /repos/acme/api/pulls/7/reviews" || auth[0] != "Bearer ghs_777" {
		t.Errorf("posts: %v auth=%v", seen, auth)
	}
	// 5. The request names no PR: verdict only, and it says so.
	if resp := call(strings.Replace(prBody, `"repository": "acme/api", "pull_number": 7, "head_sha": "abc123"`, `"repository": ""`, 1)); resp["posted"] != false || !strings.Contains(resp["not_posted_reason"].(string), "named no pull request") {
		t.Errorf("no PR named: %v", resp)
	}
	// 6. GitHub refuses → posted false with GitHub's reason, and the verdict still returned.
	if resp := call(strings.Replace(prBody, "acme/api", "acme/broken", 1)); resp["posted"] != false || !strings.Contains(resp["not_posted_reason"].(string), "checks: write") || resp["blocked"] != true {
		t.Errorf("refused post: %v", resp)
	}
	// 7. The App cannot mint a token → the reason is the mint error, never a request with no bearer.
	d.GitHubApp = fakeApp{err: errors.New("ghapp: HTTP 404 — installation 777 does not belong to this App")}
	if resp := call(prBody); resp["posted"] != false || !strings.Contains(resp["not_posted_reason"].(string), "does not belong") {
		t.Errorf("mint failure: %v", resp)
	}
}

// Settings: the installation id is recorded on the GitHub connection (refused without one, refused
// non-numeric), and GET reports the three facts + the conjunction the pr-check will act on.
func TestPRBotSettings_InstallationIDAndPostingStatus(t *testing.T) {
	ctx := context.Background()
	d := enabledPRBot(t)
	put := func(body string) (int, string) {
		rec := httptest.NewRecorder()
		d.handlePutPRBotSettings(rec, httptest.NewRequest(http.MethodPut, "/v1/settings/pr-bot", strings.NewReader(body)), "ten-1")
		return rec.Code, rec.Body.String()
	}
	get := func() map[string]any {
		rec := httptest.NewRecorder()
		d.handleGetPRBotSettings(rec, httptest.NewRequest(http.MethodGet, "/v1/settings/pr-bot", nil), "ten-1")
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return m
	}
	if code, body := put(`{"enabled":true,"block_severity":"high","installation_id":"777"}`); code != http.StatusBadRequest || !strings.Contains(body, "connect GitHub") {
		t.Errorf("no GitHub connection must refuse the id: %d %s", code, body)
	}
	_ = d.Store.PutConnection(ctx, platform.Connection{ID: "gh", TenantID: "ten-1", Kind: platform.ConnGitHub, Status: platform.ConnActive})
	if code, body := put(`{"enabled":true,"block_severity":"high","installation_id":"abc"}`); code != http.StatusBadRequest || !strings.Contains(body, "numeric") {
		t.Errorf("non-numeric must be refused: %d %s", code, body)
	}
	if code, _ := put(`{"enabled":true,"block_severity":"high","installation_id":"777"}`); code != http.StatusOK {
		t.Fatalf("record: %d", code)
	}
	g := get()
	if g["installation_id"] != "777" || g["app_configured"] != false || g["posting_live"] != false || !strings.Contains(g["not_posting_reason"].(string), "no GitHub App") {
		t.Errorf("without an App the status must say so: %v", g)
	}
	d.GitHubApp = fakeApp{}
	if g := get(); g["posting_live"] != true || g["not_posting_reason"] != "" {
		t.Errorf("with App + connection + id the status is live: %v", g)
	}
	// A PUT that omits installation_id leaves it alone; "" clears it.
	if code, _ := put(`{"enabled":false,"block_severity":"off"}`); code != http.StatusOK {
		t.Fatal("omit")
	}
	if g := get(); g["installation_id"] != "777" {
		t.Errorf("omitting the field must not clear it: %v", g)
	}
	if code, _ := put(`{"enabled":false,"block_severity":"off","installation_id":""}`); code != http.StatusOK {
		t.Fatal("clear")
	}
	if g := get(); g["installation_id"] != "" || g["posting_live"] != false {
		t.Errorf("an empty id clears it: %v", g)
	}
}
