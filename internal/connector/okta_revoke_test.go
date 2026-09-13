package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// session_revoke and oauth_revoke are LIVE Okta writes: each hits exactly the documented DELETE,
// per user for grants, and a failing user is collected rather than skipped.
func TestOkta_SessionAndGrantRevokeHitTheDocumentedEndpoints(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "bad request", 400)
			return
		}
		deleted = append(deleted, r.URL.Path)
		if strings.Contains(r.URL.Path, "/users/00u-broken/") {
			http.Error(w, `{"errorCode":"E0000007"}`, 404)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	o := &Okta{OrgURL: srv.URL, HTTP: srv.Client()}
	conn := platform.Connection{ID: "c1", Kind: platform.ConnOkta, Scopes: []string{oktaWriteScope}}

	sess := platform.Action{ID: "a1", Kind: platform.ActApplyConfig, Payload: map[string]any{"remediation_type": "session_revoke", "target": "ada@acme.io"}}
	if err := o.Apply(context.Background(), conn, "tok", sess); err != nil {
		t.Fatalf("session_revoke: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "/api/v1/users/ada@acme.io/sessions" {
		t.Errorf("session revoke path: %v", deleted)
	}

	deleted = nil
	grants := platform.Action{ID: "a2", Kind: platform.ActApplyConfig, Payload: map[string]any{
		"remediation_type": "oauth_revoke", "target": "Shadow Admin App", "client_id": "0oa-app", "user_ids": "00u-1,00u-broken,00u-2"}}
	err := o.Apply(context.Background(), conn, "tok", grants)
	if err == nil || !strings.Contains(err.Error(), "revoked grants for 2 user(s)") || !strings.Contains(err.Error(), "00u-broken") {
		t.Fatalf("a partial failure must be reported with the count revoked and the user that failed: %v", err)
	}
	want := map[string]bool{"/api/v1/users/00u-1/clients/0oa-app/grants": true, "/api/v1/users/00u-broken/clients/0oa-app/grants": true, "/api/v1/users/00u-2/clients/0oa-app/grants": true}
	if len(deleted) != 3 {
		t.Fatalf("every user must be attempted: %v", deleted)
	}
	for _, p := range deleted {
		if !want[p] {
			t.Errorf("unexpected path %s", p)
		}
	}

	// Preflight: no ids → refused before anyone is asked to approve; missing write scope → refused.
	noIDs := platform.Action{ID: "a3", Payload: map[string]any{"remediation_type": "oauth_revoke", "target": "App"}}
	if err := o.Preflight(conn, noIDs); err == nil || !strings.Contains(err.Error(), "names no client id") {
		t.Errorf("preflight without ids: %v", err)
	}
	readOnly := platform.Connection{ID: "c2", Kind: platform.ConnOkta, Scopes: []string{"okta.users.read"}}
	if err := o.Preflight(readOnly, sess); err == nil {
		t.Error("preflight must refuse a session revoke without the write scope")
	}
}
