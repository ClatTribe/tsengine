package webagent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// TestWebAgent_Live drives the offensive web agent against a SELF-CONTAINED vulnerable target (a local
// httptest open-redirect endpoint), seeded with the suspected class so the agent confirms it. Asserts
// the loop runs + reports; landing a proven finding is model/budget-dependent so it's logged. Skipped
// unless LLM_BASE_URL is set (CI-safe). Part-4 harness — no external target needed:
//
//	LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3:8b LLM_API_KEY=ollama \
//	  go test ./internal/webagent -run TestWebAgent_Live -v -timeout 20m
func TestWebAgent_Live(t *testing.T) {
	base := os.Getenv("LLM_BASE_URL")
	if base == "" {
		t.Skip("set LLM_BASE_URL (e.g. http://localhost:11434/v1) to run the live web-agent test")
	}
	model := os.Getenv("LLM_MODEL")
	if model == "" {
		model = "qwen3:8b"
	}
	// A deliberately-vulnerable target: /redirect reflects ?url into a 302 Location (open redirect).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/redirect?url=/home">go</a></body></html>`))
	}))
	defer srv.Close()

	llm := cloudengine.NewOpenAICompat(os.Getenv("LLM_API_KEY"), model, base)
	cc := &Context{Target: srv.URL}
	rep, err := Investigate(context.Background(), llm, cc, Options{
		MaxIters:    5,
		MaxRequests: 15,
		SeedFindings: []SeedFinding{
			{Route: srv.URL + "/redirect?url=", Class: "open_redirect", Tool: "test", Severity: "medium"},
		},
	})
	if err != nil {
		t.Fatalf("%s drove the web agent to an error: %v", model, err)
	}
	t.Logf("PASS: %s drove the web agent against a live open-redirect target — %d finding(s), %d request(s), %d tool call(s)",
		model, len(rep.Findings), rep.Requests, rep.Calls)
	for _, f := range rep.Findings {
		t.Logf("  finding class=%s verified=%v", f.Class, f.Verified)
	}
	// The loop must make real progress: send at least one HTTP request to the target.
	if rep.Requests == 0 {
		t.Errorf("the web agent sent 0 requests — the model produced no probes")
	}
}
