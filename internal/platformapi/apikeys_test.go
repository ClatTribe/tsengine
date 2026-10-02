package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// putKey stores a key for tenant t1 with the given scopes and returns the raw key.
func putKey(t *testing.T, st store.Store, id string, scopes ...string) string {
	t.Helper()
	raw, err := mintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.PutAPIKey(context.Background(), platform.APIKey{
		ID: id, TenantID: "t1", Name: id, Prefix: raw[:12], Hash: apiKeyDigest(raw), Scopes: scopes,
		CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return raw
}

// THE GUARD THAT MAKES THE SCOPES REAL. Every route in api.go goes through the auth gate with a read
// key, an ingest key and a key holding both, and each must reach exactly what apiKeyMayReach says —
// enumerated, because the route this misses is the one a leaked CI key uses to approve a fix.
func TestAPIKeyReachesExactlyItsScopes(t *testing.T) {
	routes := registeredRoutes(t)
	if len(routes) < 100 {
		t.Fatalf("only %d routes parsed from api.go — the guard is covering almost nothing", len(routes))
	}
	d, st := ownerScopeDeps(t)
	keys := map[string]platform.APIKey{}
	raws := map[string]string{}
	for name, scopes := range map[string][]string{
		"read":   {platform.APIKeyScopeRead},
		"ingest": {platform.APIKeyScopeIngest},
		"both":   {platform.APIKeyScopeRead, platform.APIKeyScopeIngest},
	} {
		raws[name] = putKey(t, st, name, scopes...)
		keys[name] = platform.APIKey{Scopes: scopes}
	}
	wild := regexp.MustCompile(`\{[^}]+\}`)

	reached := map[string]int{}
	for _, rt := range routes {
		path := wild.ReplaceAllString(rt.path, "x1")
		for name, raw := range raws {
			called := false
			h := d.auth(func(http.ResponseWriter, *http.Request, string) { called = true })
			req := httptest.NewRequest(rt.method, path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+raw)
			rec := httptest.NewRecorder()
			h(rec, req)

			want := apiKeyMayReach(keys[name], rt.method, path)
			switch {
			case want && !called:
				t.Errorf("%s key refused %s %s (%d) though its scope names it", name, rt.method, rt.path, rec.Code)
			case !want && called:
				t.Errorf("%s key REACHED %s %s, which its scopes do not name", name, rt.method, rt.path)
			case !want && (rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "api_key_scope")):
				t.Errorf("%s key refused %s %s with %d %s, want 403 api_key_scope", name, rt.method, rt.path, rec.Code, rec.Body)
			}
			if called {
				reached[name]++
			}
		}
	}
	// Floors, so a matcher that stopped matching cannot pass by admitting nothing.
	if reached["ingest"] != len(ingestRoutes) {
		t.Errorf("an ingest key reached %d routes, want exactly the %d on the ingest list", reached["ingest"], len(ingestRoutes))
	}
	if reached["read"] < 50 {
		t.Errorf("a read key reached only %d routes — the GET match has stopped working", reached["read"])
	}
	if reached["both"] != reached["read"]+reached["ingest"]-1 { // GET /v1/jobs/{id} is in both
		t.Errorf("a key with both scopes reached %d routes, want the union (%d)", reached["both"], reached["read"]+reached["ingest"]-1)
	}
}

// The acts that need a named human, pinned by name against the most powerful key there is.
func TestNoAPIKeyCanDecide(t *testing.T) {
	both := platform.APIKey{Scopes: []string{platform.APIKeyScopeRead, platform.APIKeyScopeIngest}}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/v1/approvals/a1"},
		{http.MethodPost, "/v1/approvals/bulk"},
		{http.MethodPost, "/v1/killswitch"},
		{http.MethodPost, "/v1/issues/ignore"},
		{http.MethodPost, "/v1/risks/r1/decision"},
		{http.MethodPost, "/v1/program/p1/publish"},
		{http.MethodPost, "/v1/pentest/e1/signoff"},
		{http.MethodPost, "/v1/audit-review/certificate"},
		{http.MethodPut, "/v1/settings/llm"},
		{http.MethodPost, "/v1/settings/api-keys"}, // a key must not mint keys
		{http.MethodPost, "/v1/settings/api-keys/k1/revoke"},
		{http.MethodPost, "/v1/trust-requests/r1/decision"},
		{http.MethodPost, "/v1/connections/c1/quarantine"},
	} {
		if apiKeyMayReach(both, c.method, c.path) {
			t.Errorf("an API key may reach %s %s — that act needs a named human", c.method, c.path)
		}
	}
}

func TestEveryIngestEntryIsARealRoute(t *testing.T) {
	registered := map[string]bool{}
	for _, rt := range registeredRoutes(t) {
		registered[rt.method+" "+rt.path] = true
	}
	for _, a := range ingestRoutes {
		if !registered[a.method+" "+a.path] {
			t.Errorf("ingestRoutes lists %s %s, which api.go does not register — it grants nothing", a.method, a.path)
		}
	}
}

// The full lifecycle through the real gate: the owner mints a key, it is shown once and stored only
// as a digest, it authenticates as ITS tenant whatever header is sent, and revocation and expiry end it.
func TestAPIKeyLifecycle(t *testing.T) {
	d, st := ownerScopeDeps(t)
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t2"}); err != nil {
		t.Fatal(err)
	}

	rec := memberOwnerCall(d, d.handleCreateAPIKey, "own", http.MethodPost, "/v1/settings/api-keys",
		`{"name":"github-actions","scopes":["ingest"]}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("owner create: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		Key   platform.APIKey `json:"key"`
		Token string          `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, platform.APIKeyPrefix) || created.Key.Hash != "" {
		t.Fatalf("create must return the key once and never its digest: token=%q hash=%q", created.Token, created.Key.Hash)
	}
	if created.Key.CreatedBy != "ada@acme.io" {
		t.Errorf("creator must come from the session, got %q", created.Key.CreatedBy)
	}
	if days := created.Key.ExpiresAt.Sub(created.Key.CreatedAt).Hours() / 24; days < 89 || days > 91 {
		t.Errorf("default expiry is 90 days, got %.1f", days)
	}

	// Only the digest is stored — the key appears nowhere in the stored record.
	stored, _ := st.ListAPIKeys(ctx, "t1")
	raw, _ := json.Marshal(stored)
	if len(stored) != 1 || strings.Contains(string(raw), created.Token) || stored[0].Hash != apiKeyDigest(created.Token) {
		t.Fatalf("the key must be stored as its digest only: %s", raw)
	}

	// Listing never returns a digest.
	list := memberOwnerCall(d, d.handleListAPIKeys, "mem", http.MethodGet, "/v1/settings/api-keys", "", nil)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), stored[0].Hash) {
		t.Fatalf("list leaked a digest or failed: %d %s", list.Code, list.Body)
	}

	// The key authenticates as ITS tenant — a spoofed header cannot move it.
	use := func() (int, string) {
		var got string
		h := d.auth(func(_ http.ResponseWriter, _ *http.Request, tid string) { got = tid })
		req := httptest.NewRequest(http.MethodPost, "/v1/ci/pr-check", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+created.Token)
		req.Header.Set("X-Tenant-ID", "t2")
		r := httptest.NewRecorder()
		h(r, req)
		return r.Code, got
	}
	if code, tid := use(); tid != "t1" {
		t.Fatalf("an ingest key must authenticate as its own tenant: code=%d tenant=%q", code, tid)
	}
	if k, _ := st.GetAPIKeyByHash(ctx, apiKeyDigest(created.Token)); k.LastUsedAt.IsZero() {
		t.Error("a used key must record when it was last used, or nobody can tell whether it is safe to revoke")
	}

	// A member cannot revoke (owner-only by the settings prefix, enforced in the gate).
	mrev := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/settings/api-keys/"+created.Key.ID+"/revoke", nil)
	req.SetPathValue("id", created.Key.ID)
	req.Header.Set("Authorization", "Bearer sess-mem")
	d.auth(d.handleRevokeAPIKey)(mrev, req)
	if mrev.Code != http.StatusForbidden {
		t.Fatalf("a member revoking a key: %d, want 403", mrev.Code)
	}

	rev := memberOwnerCall(d, d.handleRevokeAPIKey, "own", http.MethodPost, "/v1/settings/api-keys/x/revoke", "",
		map[string]string{"id": created.Key.ID})
	if rev.Code != http.StatusOK {
		t.Fatalf("owner revoke: %d %s", rev.Code, rev.Body)
	}
	if code, tid := use(); code != http.StatusUnauthorized || tid != "" {
		t.Fatalf("a revoked key must be refused 401: code=%d tenant=%q", code, tid)
	}
	// The reason is specific: "revoked" and "expired" send a pipeline owner to different fixes.
	rr := httptest.NewRecorder()
	rq := httptest.NewRequest(http.MethodPost, "/v1/ci/pr-check", strings.NewReader("{}"))
	rq.Header.Set("Authorization", "Bearer "+created.Token)
	d.auth(func(http.ResponseWriter, *http.Request, string) {})(rr, rq)
	if !strings.Contains(rr.Body.String(), "revoked") {
		t.Errorf("a revoked key must be refused as revoked, got %s", rr.Body)
	}
	// Revocation is recorded, not a delete — the record of what the key did keeps its referent.
	if after, _ := st.ListAPIKeys(ctx, "t1"); len(after) != 1 || after[0].RevokedBy != "ada@acme.io" {
		t.Fatalf("revocation must be recorded on the key, got %+v", after)
	}

	// An expired key and an unknown key are refused too.
	expRaw, _ := mintAPIKey()
	past := time.Now().Add(-48 * time.Hour)
	_ = st.PutAPIKey(ctx, platform.APIKey{ID: "old", TenantID: "t1", Hash: apiKeyDigest(expRaw),
		Scopes: []string{platform.APIKeyScopeIngest}, CreatedAt: past, ExpiresAt: past.Add(time.Hour)})
	for name, tok := range map[string]string{"expired": expRaw, "unknown": platform.APIKeyPrefix + "deadbeef"} {
		h := d.auth(func(http.ResponseWriter, *http.Request, string) { t.Errorf("%s key reached the handler", name) })
		r := httptest.NewRequest(http.MethodPost, "/v1/ci/pr-check", strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s key: %d, want 401", name, w.Code)
		}
		if want := map[string]string{"expired": "expired", "unknown": "invalid API key"}[name]; !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s key refused without saying so: %s", name, w.Body)
		}
	}
}

func TestCreateAPIKeyValidation(t *testing.T) {
	d, _ := ownerScopeDeps(t)
	for body, want := range map[string]int{
		`{"name":"ci","scopes":[]}`:                             http.StatusBadRequest, // no scope is refused, not defaulted
		`{"name":"ci","scopes":["admin"]}`:                      http.StatusBadRequest, // there is no deciding scope
		`{"name":"","scopes":["read"]}`:                         http.StatusBadRequest,
		`{"name":"ci","scopes":["read"],"expires_in_days":400}`: http.StatusBadRequest, // no key lives past a year
		`{"name":"ci","scopes":["read"],"expires_in_days":-1}`:  http.StatusBadRequest,
		`{"name":"ci","scopes":["read","READ"]}`:                http.StatusCreated,
	} {
		rec := memberOwnerCall(d, d.handleCreateAPIKey, "own", http.MethodPost, "/v1/settings/api-keys", body, nil)
		if rec.Code != want {
			t.Errorf("%s: %d %s, want %d", body, rec.Code, rec.Body, want)
		}
	}
	// A member cannot mint a key: the settings prefix is owner-only in the gate.
	if rec := memberOwnerCall(d, d.handleCreateAPIKey, "mem", http.MethodPost, "/v1/settings/api-keys",
		`{"name":"ci","scopes":["read"]}`, nil); !isOwnerOnlyRefusal(rec) {
		t.Errorf("a member minting a key: %d %s, want 403 owner_only", rec.Code, rec.Body)
	}
}

// A session token that happens to begin with the key prefix must still sign in.
func TestSessionTokenWithKeyPrefixStillSignsIn(t *testing.T) {
	d, st := ownerScopeDeps(t)
	tok := platform.APIKeyPrefix + "looks-like-a-key"
	if err := st.PutSession(context.Background(), platform.Session{Token: tok, UserID: "u-own", TenantID: "t1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	called := false
	req := httptest.NewRequest(http.MethodGet, "/v1/issues", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	d.auth(func(http.ResponseWriter, *http.Request, string) { called = true })(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("a real session refused because its token began with the key prefix")
	}
}

// End to end through the REAL router (NewHandler), not a handler called directly: the owner mints a key
// over HTTP, the key then drives an ingest route and a GET for its own tenant, and is refused a
// decision route. The direct-handler tests above prove each piece; this proves the routes are wired.
func TestAPIKeyEndToEndThroughTheRouter(t *testing.T) {
	d, st := ownerScopeDeps(t)
	_ = st.PutFinding(context.Background(), "t1", types.Finding{ID: "f1", RuleID: "semgrep::x", Severity: types.SeverityHigh, Endpoint: "app.go:1"})
	srv := httptest.NewServer(NewHandler(d))
	defer srv.Close()

	do := func(method, path, auth, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+auth)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}

	code, body := do(http.MethodPost, "/v1/settings/api-keys", "sess-own", `{"name":"ci","scopes":["read","ingest"]}`)
	if code != http.StatusCreated {
		t.Fatalf("mint through the router: %d %s", code, body)
	}
	var created struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal([]byte(body), &created)

	if code, body := do(http.MethodGet, "/v1/issues", created.Token, ""); code != http.StatusOK || !strings.Contains(body, "semgrep::x") {
		t.Fatalf("a read key must list its own tenant's issues: %d %s", code, body)
	}
	if code, body := do(http.MethodPost, "/v1/ci/pr-check", created.Token, `{"changed_files":[],"findings":[]}`); code == http.StatusUnauthorized || code == http.StatusForbidden {
		t.Fatalf("an ingest key must reach the PR check: %d %s", code, body)
	}
	if code, body := do(http.MethodPost, "/v1/killswitch", created.Token, `{"halted":true}`); code != http.StatusForbidden || !strings.Contains(body, "api_key_scope") {
		t.Fatalf("a key must be refused the kill-switch: %d %s", code, body)
	}
	if code, _ := do(http.MethodPost, "/v1/settings/api-keys", created.Token, `{"name":"x","scopes":["read"]}`); code != http.StatusForbidden {
		t.Fatalf("a key minted another key: %d", code)
	}
}

// The Settings panel reads the PRESENCE of revoked_at as "revoked". A fresh key must not carry the field
// at all — `omitempty` on a time.Time ships "0001-01-01T00:00:00Z", which would show every key revoked.
func TestFreshKeyListingCarriesNoRevokedAt(t *testing.T) {
	d, st := ownerScopeDeps(t)
	putKey(t, st, "fresh", platform.APIKeyScopeRead)
	rec := memberOwnerCall(d, d.handleListAPIKeys, "own", http.MethodGet, "/v1/settings/api-keys", "", nil)
	if strings.Contains(rec.Body.String(), "revoked_at") || strings.Contains(rec.Body.String(), "last_used_at") {
		t.Fatalf("a fresh key's listing carries revoked_at/last_used_at — the page would show it revoked: %s", rec.Body)
	}
}
