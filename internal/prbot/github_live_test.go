package prbot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// The live poster hits the two GitHub endpoints with the installation token as bearer and the
// payloads Submit built; a 403 names the App permission the call needs.
func TestGitHubPoster_PostsCheckRunThenReviewWithTheInstallationToken(t *testing.T) {
	var seen []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghs_inst" {
			w.WriteHeader(401)
			return
		}
		seen = append(seen, r.Method+" "+r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		bodies = append(bodies, m)
		if strings.HasSuffix(r.URL.Path, "/check-runs") && r.URL.Path != "/repos/acme/api/check-runs" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
			return
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()

	p := &GitHubPoster{APIBase: srv.URL, Token: func(context.Context) (string, error) { return "ghs_inst", nil }}
	rev := Build([]types.Finding{{ID: "f1", RuleID: "gitleaks::aws-key", Severity: types.SeverityHigh, Title: "AWS key", Endpoint: "cfg.py:12"}},
		[]ChangedFile{{Path: "cfg.py", Lines: map[int]bool{12: true}}}, types.SeverityHigh)
	_, chk, err := Submit(context.Background(), rev, "acme", "api", 7, "abc123", p)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "POST /repos/acme/api/check-runs" || seen[1] != "POST /repos/acme/api/pulls/7/reviews" {
		t.Fatalf("check-run must be posted first, then the review: %v", seen)
	}
	if bodies[0]["head_sha"] != "abc123" || bodies[0]["conclusion"] != chk.Conclusion || bodies[0]["name"] != "tsengine/security" {
		t.Errorf("check-run body: %v", bodies[0])
	}
	if bodies[1]["event"] != "REQUEST_CHANGES" || len(bodies[1]["comments"].([]any)) != 1 {
		t.Errorf("review body: %v", bodies[1])
	}

	// A 403 on the check-run names `checks: write`, and the review is NOT attempted after it.
	seen = nil
	_, _, err = Submit(context.Background(), rev, "acme", "web", 3, "def", p)
	if err == nil || !strings.Contains(err.Error(), "checks: write") {
		t.Errorf("a 403 must name the permission: %v", err)
	}
	if len(seen) != 1 {
		t.Errorf("after the check-run fails the review must not be posted: %v", seen)
	}

	// A token source that fails is the error, never a request with an empty bearer.
	bad := &GitHubPoster{APIBase: srv.URL, Token: func(context.Context) (string, error) { return "", io.ErrUnexpectedEOF }}
	if err := bad.PostCheckRun(context.Background(), "acme", "api", CheckRunPayload{}); err == nil {
		t.Error("a failed token mint must surface")
	}
}
