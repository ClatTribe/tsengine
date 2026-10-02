package uicheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// API keys are a credential, so the page's job is narrow and each part of it is load-bearing: show the
// key once (from the create response — the server keeps only a digest, so there is no second chance),
// render what each scope grants in the server's own words (a person choosing a scope should read what
// it allows, not infer it from one word), never render a digest, and offer mint/revoke only to the
// owner the server lets do it. FAILS rather than skips when a file moves.
func TestAPIKeysPanelShowsTheKeyOnceAndTheServerScopes(t *testing.T) {
	ctl := stripComments(frontendFile(t, "components", "settings", "api-keys-control.tsx"))
	for _, want := range []struct{ s, why string }{
		{"minted.token", "the key must be shown from the create response, the only time it exists"},
		{"shown once", "the panel must say the key will not be shown again"},
		{"Object.entries(scopes)", "scope descriptions must be the server's, not the page's own wording"},
		{"canManage", "mint and revoke must be gated on the role the server gates on"},
		{"never used", "a key nobody has used must say so — it is the first thing to check before revoking"},
	} {
		if !strings.Contains(ctl, want.s) {
			t.Errorf("api keys panel: %s (missing %q)", want.why, want.s)
		}
	}
	if strings.Contains(ctl, ".hash") {
		t.Error("the api keys panel reads a key digest — the server never sends one and the page must not show one")
	}
	page := stripComments(frontendFile(t, "app", "(app)", "settings", "page.tsx"))
	if !strings.Contains(page, "canManage={isOwner}") {
		t.Error("settings must pass the owner flag to the api keys panel")
	}
}

// The CI template is where customers learn which credential to paste. It used to say "a tenant API
// token (X-Tenant-ID is carried by the session token)" — i.e. a person's session, which expires under
// the job and can approve fixes. It must name the ingest key.
func TestCIActionAsksForAnIngestKey(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "ci", "github-action.yml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v — if the template moved, move this guard with it", path, err)
	}
	doc := string(b)
	if !strings.Contains(doc, "`ingest` scope") {
		t.Error("the GitHub Action template no longer tells customers to use an ingest-scoped API key")
	}
	if strings.Contains(doc, "carried by the session token") {
		t.Error("the GitHub Action template still tells customers to paste a session token")
	}
}
