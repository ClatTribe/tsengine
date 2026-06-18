package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A5: the Okta identity write-path (suspend a stale account) is the first live,
// HITL-gated remediation — verified against a fake Okta org so the mechanism is
// proven without live admin creds.
func TestOkta_Apply_SuspendsUser(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK) // Okta suspend → 200, empty body
	}))
	defer srv.Close()

	o := &Okta{OrgURL: srv.URL, HTTP: srv.Client()}
	a := platform.Action{
		ID:      "act-1",
		Payload: map[string]any{"remediation_type": "account_suspend", "target": "alice@acme.com"},
	}
	if err := o.Apply(context.Background(), platform.Connection{}, "tok-123", a); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method: got %s, want POST", gotMethod)
	}
	if gotPath != "/api/v1/users/alice@acme.com/lifecycle/suspend" {
		t.Errorf("path: got %q", gotPath)
	}
	if gotAuth != "Bearer tok-123" {
		t.Errorf("auth: got %q, want Bearer tok-123", gotAuth)
	}
}

func TestOkta_Apply_UnwiredTypeErrors(t *testing.T) {
	o := &Okta{OrgURL: "https://x.okta.com"}
	a := platform.Action{ID: "act-2", Payload: map[string]any{"remediation_type": "mfa_enforce", "target": "bob@acme.com"}}
	err := o.Apply(context.Background(), platform.Connection{}, "tok", a)
	if err == nil || !strings.Contains(err.Error(), "no live write path") {
		t.Fatalf("unwired type should error clearly, got: %v", err)
	}
}

func TestOkta_Apply_MissingTargetErrors(t *testing.T) {
	o := &Okta{OrgURL: "https://x.okta.com"}
	a := platform.Action{ID: "act-3", Payload: map[string]any{"remediation_type": "account_suspend"}}
	if err := o.Apply(context.Background(), platform.Connection{}, "tok", a); err == nil {
		t.Fatal("missing target must error")
	}
}

func TestOkta_Apply_SurfacesHTTPError(t *testing.T) {
	// Without okta.users.manage scope, Okta answers 403 — the action must NOT be
	// reported as applied; the error surfaces.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errorSummary":"missing scope"}`))
	}))
	defer srv.Close()

	o := &Okta{OrgURL: srv.URL, HTTP: srv.Client()}
	a := platform.Action{ID: "act-4", Payload: map[string]any{"remediation_type": "account_suspend", "target": "carol@acme.com"}}
	err := o.Apply(context.Background(), platform.Connection{}, "tok", a)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("403 must surface as an error, got: %v", err)
	}
}
