package connector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// suspendAction is the gated account-suspend action the HITL desk routes to a connector Apply.
func suspendAction(target string) platform.Action {
	return platform.Action{
		ID:      "act-1",
		Kind:    platform.ActApplyConfig,
		Payload: map[string]any{"remediation_type": "account_suspend", "target": target},
	}
}

func TestGWorkspace_ApplySuspendsUser(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"primaryEmail":"stale@acme.io","suspended":true}`))
	}))
	defer srv.Close()

	g := &GWorkspace{APIBase: srv.URL, HTTP: srv.Client()}
	if err := g.Apply(context.Background(), platform.Connection{}, "tok-abc", suspendAction("stale@acme.io")); err != nil {
		t.Fatalf("suspend should succeed: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("want PUT, got %s", gotMethod)
	}
	if gotPath != "/admin/directory/v1/users/stale@acme.io" {
		t.Errorf("wrong path: %s", gotPath)
	}
	if gotAuth != "Bearer tok-abc" {
		t.Errorf("wrong auth: %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"suspended":true`) {
		t.Errorf("body should set suspended=true, got %q", gotBody)
	}
}

func TestGWorkspace_ApplySurfaces403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"insufficient permission"}}`))
	}))
	defer srv.Close()
	g := &GWorkspace{APIBase: srv.URL, HTTP: srv.Client()}
	err := g.Apply(context.Background(), platform.Connection{}, "tok", suspendAction("u@acme.io"))
	if err == nil || !strings.Contains(err.Error(), "admin.directory.user write scope") {
		t.Errorf("a 403 must surface the missing write scope, got %v", err)
	}
}

func TestGWorkspace_ApplyUnknownTypeIsError(t *testing.T) {
	g := &GWorkspace{APIBase: "http://unused", HTTP: http.DefaultClient}
	a := platform.Action{ID: "a", Payload: map[string]any{"remediation_type": "delete_user", "target": "u@acme.io"}}
	if err := g.Apply(context.Background(), platform.Connection{}, "tok", a); err == nil {
		t.Error("an unwired remediation_type must error, not silently succeed")
	}
}

func TestM365_ApplyDisablesUser(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent) // Graph PATCH returns 204
	}))
	defer srv.Close()

	m := &M365{GraphBase: srv.URL, HTTP: srv.Client()}
	if err := m.Apply(context.Background(), platform.Connection{}, "tok-xyz", suspendAction("stale@acme.io")); err != nil {
		t.Fatalf("disable should succeed: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("want PATCH, got %s", gotMethod)
	}
	if gotPath != "/users/stale@acme.io" {
		t.Errorf("wrong path: %s", gotPath)
	}
	if gotAuth != "Bearer tok-xyz" {
		t.Errorf("wrong auth: %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"accountEnabled":false`) {
		t.Errorf("body should set accountEnabled=false, got %q", gotBody)
	}
}

func TestM365_ApplySurfaces403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Authorization_RequestDenied"}}`))
	}))
	defer srv.Close()
	m := &M365{GraphBase: srv.URL, HTTP: srv.Client()}
	err := m.Apply(context.Background(), platform.Connection{}, "tok", suspendAction("u@acme.io"))
	if err == nil || !strings.Contains(err.Error(), "User.ReadWrite.All write scope") {
		t.Errorf("a 403 must surface the missing write scope, got %v", err)
	}
}

func TestM365_ApplyUnknownTypeIsError(t *testing.T) {
	m := &M365{GraphBase: "http://unused", HTTP: http.DefaultClient}
	a := platform.Action{ID: "a", Payload: map[string]any{"remediation_type": "delete_user", "target": "u@acme.io"}}
	if err := m.Apply(context.Background(), platform.Connection{}, "tok", a); err == nil {
		t.Error("an unwired remediation_type must error, not silently succeed")
	}
}
