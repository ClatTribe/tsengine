package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestClient_Execute_Success(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tool.Result{
			Findings: []types.SandboxEmittedFinding{
				{RuleID: "test-rule", Tool: "nuclei", Severity: types.SeverityHigh, Title: "t"},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(&Info{APIURL: srv.URL, AuthToken: "tok-abc"})
	res, err := c.Execute(context.Background(), "nuclei", tool.Args{"target": "https://x"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotPath != "/execute" {
		t.Errorf("path: got %q, want /execute", gotPath)
	}
	if gotAuth != "Bearer tok-abc" {
		t.Errorf("auth: got %q, want %q", gotAuth, "Bearer tok-abc")
	}
	if !strings.Contains(gotBody, `"tool":"nuclei"`) {
		t.Errorf("body missing tool name: %s", gotBody)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "test-rule" {
		t.Errorf("findings: %+v", res.Findings)
	}
}

func TestClient_Execute_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "tool exploded", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(&Info{APIURL: srv.URL, AuthToken: "x"})
	_, err := c.Execute(context.Background(), "nuclei", nil)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status: %v", err)
	}
}

func TestClient_Execute_EmptyToolName(t *testing.T) {
	c := NewClient(&Info{APIURL: "http://example", AuthToken: "x"})
	_, err := c.Execute(context.Background(), "", nil)
	if err == nil || !strings.Contains(err.Error(), "empty tool name") {
		t.Errorf("expected empty-tool error; got %v", err)
	}
}

func TestClient_Healthz_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(&Info{APIURL: srv.URL})
	if err := c.Healthz(context.Background()); err != nil {
		t.Errorf("Healthz: %v", err)
	}
}

func TestClient_Healthz_Bad(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewClient(&Info{APIURL: srv.URL})
	if err := c.Healthz(context.Background()); err == nil {
		t.Error("expected Healthz error for 503")
	}
}
