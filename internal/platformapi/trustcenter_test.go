package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/trustcenter"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Everything here drives the real mux rather than calling the handler functions directly.
// The distinction has bitten this codebase before: a direct-call test passes with the route
// removed, so it proves the decision and not that anyone can reach it — and for a gate, being
// reachable by the wrong person is the whole failure.

func tcDeps(t *testing.T) (Deps, http.Handler, *store.Memory) {
	t.Helper()
	// The request limiter is package-level and every httptest request shares one RemoteAddr, so
	// without this the sixth access request in the whole suite 429s and the test that made it
	// fails somewhere unrelated.
	trustRequestLimiter.reset()
	st := store.NewMemory()
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	return d, NewHandler(d), st
}

func seedTrustTenant(t *testing.T, st *store.Memory, id, name string, cfg platform.TrustCenterConfig) {
	t.Helper()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: id, Name: name, TrustCenter: &cfg}); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, h http.Handler, url string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
	return rec
}

func post(t *testing.T, h http.Handler, url, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec2 := rec
	h.ServeHTTP(rec2, req)
	return rec2
}

func authed(t *testing.T, h http.Handler, method, url, tenant, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer platform-tok")
	req.Header.Set("X-Tenant-ID", tenant)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	return rec
}

// --- the revocation fix ------------------------------------------------------------------

func TestTrustLinkRevocationKillsOnlyThatTenantsLink(t *testing.T) {
	// The defect this fixes: the share token was a bare HMAC over the tenant id, so it could
	// never be invalidated — while the public page told readers a link "has been revoked". The
	// only real remedy was rotating the platform secret, which would have taken every other
	// tenant's link with it, so the blast radius is as much the point as the revocation.
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{Enabled: true})
	seedTrustTenant(t, st, "t2", "Globex", platform.TrustCenterConfig{Enabled: true})

	before1 := d.trustTokenFor("t1", platform.TrustCenterConfig{})
	before2 := d.trustTokenFor("t2", platform.TrustCenterConfig{})
	if get(t, h, "/v1/trust/t1?token="+before1).Code != 200 {
		t.Fatal("the link did not work before revocation")
	}

	if rec := authed(t, h, "POST", "/v1/settings/trust-center/revoke-link", "t1", "{}"); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}

	if rec := get(t, h, "/v1/trust/t1?token="+before1); rec.Code != http.StatusNotFound {
		t.Errorf("the revoked link still works (%d) — revocation is decorative", rec.Code)
	}
	if rec := get(t, h, "/v1/trust/t2?token="+before2); rec.Code != 200 {
		t.Errorf("revoking t1's link broke t2's (%d) — that is the blast radius this replaces", rec.Code)
	}

	// And the newly-issued link works, or revocation would be a one-way door out of the feature.
	var link struct {
		Token string `json:"token"`
	}
	rec := authed(t, h, "GET", "/v1/trust-link", "t1", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &link)
	if link.Token == before1 {
		t.Fatal("the re-issued token is identical to the revoked one")
	}
	if got := get(t, h, "/v1/trust/t1?token="+link.Token); got.Code != 200 {
		t.Errorf("the re-issued link does not work: %d", got.Code)
	}
}

func TestTrustTokenVersionZeroAndOneAgree(t *testing.T) {
	// Existing links were issued before the version existed. If v0 and v1 diverged, deploying
	// this would silently revoke every trust link in production at once.
	d, _, _ := tcDeps(t)
	v0 := d.trustTokenFor("t1", platform.TrustCenterConfig{})
	v1 := d.trustTokenFor("t1", platform.TrustCenterConfig{TokenVersion: 1})
	if v0 != v1 {
		t.Fatalf("v0=%q v1=%q — every link issued before this change would break on deploy", v0, v1)
	}
	if v2 := d.trustTokenFor("t1", platform.TrustCenterConfig{TokenVersion: 2}); v2 == v0 {
		t.Fatal("v2 matches v0, so the first revocation would not revoke anything")
	}
}

func TestConfigSaveCannotMoveTheRevocationCounter(t *testing.T) {
	// The counter is not client-settable. A round-trip that dropped the field would otherwise
	// resurrect every link the owner had just killed, and a stale client could do it by accident.
	_, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{Enabled: true, TokenVersion: 7})
	if rec := authed(t, h, "PUT", "/v1/settings/trust-center", "t1", `{"enabled":true,"token_version":1}`); rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	got, _ := st.GetTenant(context.Background(), "t1")
	if got.TrustCenter.TokenVersion != 7 {
		t.Errorf("a config save moved the revocation counter to %d — revoked links would come back",
			got.TrustCenter.TokenVersion)
	}
}

// --- the document gate -------------------------------------------------------------------

// gatedTenant sets up a tenant offering one public and one gated document, both available.
func gatedTenant(t *testing.T, st *store.Memory) platform.TrustCenterConfig {
	t.Helper()
	cfg := platform.TrustCenterConfig{
		Enabled: true,
		Subprocessors: []platform.Subprocessor{
			{Name: "Amazon Web Services", Purpose: "Hosting", Location: "eu-west-1"},
		},
		Documents: []platform.TrustDocument{
			{Kind: platform.DocSubprocessors, Visibility: platform.VisPublic},
			{Kind: platform.DocExternal, Visibility: platform.VisGated, URL: "https://trust.acme.test/soc2.pdf"},
		},
	}
	seedTrustTenant(t, st, "t1", "Acme", cfg)
	return cfg
}

func TestGatedDocumentIsRefusedWithoutAGrant(t *testing.T) {
	d, h, st := tcDeps(t)
	gatedTenant(t, st)
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})

	if rec := get(t, h, "/v1/trust/t1/doc?token="+tok+"&kind=external"); rec.Code != http.StatusForbidden {
		t.Errorf("gated document served to an ungranted visitor: %d %s", rec.Code, rec.Body.String())
	}
	// The public one is served to the same visitor, so the refusal above is the gate and not a
	// broken endpoint.
	if rec := get(t, h, "/v1/trust/t1/doc?token="+tok+"&kind=subprocessors"); rec.Code != 200 {
		t.Errorf("public document refused: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPublicPageListsTheGatedDocumentButNeverItsLink(t *testing.T) {
	// The row has to be visible — nobody requests access to something they cannot see — but the
	// URL IS the document for an external row, so listing it would make the gate decorative.
	d, h, st := tcDeps(t)
	gatedTenant(t, st)
	rec := get(t, h, "/v1/trust/t1?token="+d.trustTokenFor("t1", platform.TrustCenterConfig{}))

	var v struct {
		Documents []trustcenter.Entry `json:"documents"`
		Granted   bool                `json:"granted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Granted {
		t.Error("a visitor with no access token is reported as granted")
	}
	if len(v.Documents) != 2 {
		t.Fatalf("want both rows listed, got %d: %+v", len(v.Documents), v.Documents)
	}
	for _, e := range v.Documents {
		if e.Kind == platform.DocExternal {
			if e.Readable {
				t.Error("gated row marked readable to an ungranted visitor")
			}
			if e.URL != "" {
				t.Errorf("gated row leaked its URL: %q", e.URL)
			}
		}
	}
	if strings.Contains(rec.Body.String(), "soc2.pdf") {
		t.Errorf("the gated document's link appears somewhere in the public payload: %s", rec.Body.String())
	}
}

func TestUnavailableDocumentIsNotListedAtAll(t *testing.T) {
	// A locked row asserts the document exists and is merely withheld. Here nothing can produce
	// a VAPT report — no scan has completed — so the row must be absent rather than teasing.
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{
		Enabled:   true,
		Documents: []platform.TrustDocument{{Kind: platform.DocVAPTReport, Visibility: platform.VisGated}},
	})
	rec := get(t, h, "/v1/trust/t1?token="+d.trustTokenFor("t1", platform.TrustCenterConfig{}))
	var v struct {
		Documents []trustcenter.Entry `json:"documents"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if len(v.Documents) != 0 {
		t.Errorf("listed a document nothing can produce: %+v", v.Documents)
	}
}

// --- the buyer flow, end to end ----------------------------------------------------------

func TestAccessRequestApprovalUnlocksExactlyOneTenant(t *testing.T) {
	d, h, st := tcDeps(t)
	gatedTenant(t, st)
	seedTrustTenant(t, st, "t2", "Globex", platform.TrustCenterConfig{
		Enabled:   true,
		Documents: []platform.TrustDocument{{Kind: platform.DocExternal, Visibility: platform.VisGated, URL: "https://trust.globex.test/soc2.pdf"}},
	})
	tok1 := d.trustTokenFor("t1", platform.TrustCenterConfig{})
	tok2 := d.trustTokenFor("t2", platform.TrustCenterConfig{})

	rec := post(t, h, "/v1/trust/t1/request?token="+tok1, `{"email":"jane@buyer.example","company":"Buyer Inc"}`)
	if rec.Code != 200 {
		t.Fatalf("request: %d %s", rec.Code, rec.Body.String())
	}
	var made struct {
		RequestID   string `json:"request_id"`
		Status      string `json:"status"`
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if made.Status != platform.TrustReqPending {
		t.Fatalf("an unmatched domain should wait for a human, got %q", made.Status)
	}
	if made.AccessToken != "" {
		t.Fatal("a pending request handed out an access token")
	}

	dec := authed(t, h, "POST", "/v1/trust-requests/"+made.RequestID+"/decision", "t1",
		`{"decision":"approve","by":"owner@acme.test"}`)
	if dec.Code != 200 {
		t.Fatalf("approve: %d %s", dec.Code, dec.Body.String())
	}
	var approved struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(dec.Body.Bytes(), &approved)
	if approved.AccessToken == "" {
		t.Fatal("approval returned no access token, so the buyer can never get in")
	}

	if rec := get(t, h, "/v1/trust/t1/doc?token="+tok1+"&kind=external&access="+approved.AccessToken); rec.Code != http.StatusFound {
		t.Errorf("granted buyer refused: %d %s", rec.Code, rec.Body.String())
	}
	// ISOLATION: the same token must be worthless at another tenant's Trust Center. A leak here
	// hands one customer's buyer another customer's documents.
	if rec := get(t, h, "/v1/trust/t2/doc?token="+tok2+"&kind=external&access="+approved.AccessToken); rec.Code != http.StatusForbidden {
		t.Errorf("ISOLATION: t1's access token opened t2's document: %d", rec.Code)
	}
}

func TestAutoApproveMatchesTheDomainAndNothingElse(t *testing.T) {
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{
		Enabled: true, AutoApproveDomains: []string{"buyer.example"},
		Subprocessors: []platform.Subprocessor{{Name: "AWS"}},
		Documents:     []platform.TrustDocument{{Kind: platform.DocSubprocessors, Visibility: platform.VisGated}},
	})
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})

	var ok struct {
		Status      string `json:"status"`
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"jane@buyer.example"}`).Body.Bytes(), &ok)
	if ok.Status != platform.TrustReqApproved || ok.AccessToken == "" {
		t.Fatalf("matching domain was not auto-approved: %+v", ok)
	}
	if rec := get(t, h, "/v1/trust/t1/doc?token="+tok+"&kind=subprocessors&access="+ok.AccessToken); rec.Code != 200 {
		t.Errorf("auto-approved buyer refused: %d", rec.Code)
	}

	// A look-alike domain is a stranger. Suffix matching here would decide who reads a
	// penetration-test report.
	var no struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"eve@notbuyer.example"}`).Body.Bytes(), &no)
	if no.Status != platform.TrustReqPending {
		t.Errorf("a look-alike domain was auto-approved: %q", no.Status)
	}
}

func TestNDAMustBeAcceptedBeforeAnyGatedDocument(t *testing.T) {
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{
		Enabled: true, NDAText: "Keep this confidential.", AutoApproveDomains: []string{"buyer.example"},
		Subprocessors: []platform.Subprocessor{{Name: "AWS"}},
		Documents:     []platform.TrustDocument{{Kind: platform.DocSubprocessors, Visibility: platform.VisGated}},
	})
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})

	var granted struct {
		AccessToken string `json:"access_token"`
		NDARequired bool   `json:"nda_required"`
	}
	_ = json.Unmarshal(post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"jane@buyer.example"}`).Body.Bytes(), &granted)
	if !granted.NDARequired || granted.AccessToken == "" {
		t.Fatalf("setup: %+v", granted)
	}

	docURL := "/v1/trust/t1/doc?token=" + tok + "&kind=subprocessors&access=" + granted.AccessToken
	if rec := get(t, h, docURL); rec.Code != http.StatusForbidden {
		t.Fatalf("approved-but-unsigned buyer got the document: %d", rec.Code)
	}
	// The page tells them WHY — waiting on a human and waiting on their own click are different
	// situations and the buyer can only act on one of them.
	var page struct {
		NDAPending bool   `json:"nda_pending"`
		NDAText    string `json:"nda_text"`
	}
	_ = json.Unmarshal(get(t, h, "/v1/trust/t1?token="+tok+"&access="+granted.AccessToken).Body.Bytes(), &page)
	if !page.NDAPending || page.NDAText == "" {
		t.Errorf("the page does not tell the buyer an agreement is outstanding: %+v", page)
	}

	if rec := post(t, h, "/v1/trust/t1/nda?token="+tok+"&access="+granted.AccessToken, `{"name":"Jane Buyer"}`); rec.Code != 200 {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(t, h, docURL); rec.Code != 200 {
		t.Errorf("still refused after accepting: %d", rec.Code)
	}

	// The DIGEST of the exact text is what was stored. A boolean would be worthless the moment
	// the tenant edited their terms — the record could not say which agreement was on screen.
	reqs, _ := st.ListTrustAccessRequests(context.Background(), "t1")
	if len(reqs) != 1 {
		t.Fatalf("want 1 request, got %d", len(reqs))
	}
	if want := trustcenter.NDAHash("Keep this confidential."); reqs[0].NDAHash != want {
		t.Errorf("NDA digest %q, want %q", reqs[0].NDAHash, want)
	}
	if reqs[0].NDAName != "Jane Buyer" {
		t.Errorf("acceptance recorded no name: %q", reqs[0].NDAName)
	}
}

func TestRevokedAndExpiredGrantsStopWorking(t *testing.T) {
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{
		Enabled: true, AutoApproveDomains: []string{"buyer.example"},
		Subprocessors: []platform.Subprocessor{{Name: "AWS"}},
		Documents:     []platform.TrustDocument{{Kind: platform.DocSubprocessors, Visibility: platform.VisGated}},
	})
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})
	var g struct {
		RequestID   string `json:"request_id"`
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"jane@buyer.example"}`).Body.Bytes(), &g)
	docURL := "/v1/trust/t1/doc?token=" + tok + "&kind=subprocessors&access=" + g.AccessToken
	if get(t, h, docURL).Code != 200 {
		t.Fatal("setup: the grant does not work")
	}

	if rec := authed(t, h, "POST", "/v1/trust-requests/"+g.RequestID+"/decision", "t1",
		`{"decision":"revoke","by":"owner@acme.test"}`); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(t, h, docURL); rec.Code != http.StatusForbidden {
		t.Errorf("a revoked grant still opens the document: %d", rec.Code)
	}

	// Expiry is the other end of the same guarantee, and it is what stops access outliving the
	// deal when nobody remembers to revoke.
	reqs, _ := st.ListTrustAccessRequests(context.Background(), "t1")
	expired := reqs[0]
	expired.Revoked = false
	expired.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	_ = st.PutTrustAccessRequest(context.Background(), expired)
	if rec := get(t, h, docURL); rec.Code != http.StatusForbidden {
		t.Errorf("an expired grant still opens the document: %d", rec.Code)
	}
}

func TestOwnerDeskNeverReturnsTheTokenHash(t *testing.T) {
	// The hash is the only thing between a stored record and working access to the gated tier.
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{Enabled: true, AutoApproveDomains: []string{"buyer.example"}})
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})
	_ = post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"jane@buyer.example"}`)

	reqs, _ := st.ListTrustAccessRequests(context.Background(), "t1")
	if reqs[0].TokenHash == "" {
		t.Fatal("setup: no token hash was stored")
	}
	body := authed(t, h, "GET", "/v1/trust-requests", "t1", "").Body.String()
	if strings.Contains(body, reqs[0].TokenHash) {
		t.Error("the access desk returned the stored token hash")
	}
	if strings.Contains(body, `"token_hash"`) && !strings.Contains(body, `"token_hash":""`) {
		t.Errorf("token_hash present in the desk payload: %s", body)
	}
}

func TestApprovalRequiresANamedHuman(t *testing.T) {
	// A rule approving and a person approving are different facts, and the log has to be able to
	// tell them apart. Accepting a blank name would make every auto-approval look reviewed.
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{Enabled: true})
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})
	var made struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"jane@buyer.example"}`).Body.Bytes(), &made)

	rec := authed(t, h, "POST", "/v1/trust-requests/"+made.RequestID+"/decision", "t1", `{"decision":"approve"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unsigned approval was accepted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestViewsAreLogged(t *testing.T) {
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{
		Enabled: true, AutoApproveDomains: []string{"buyer.example"},
		Subprocessors: []platform.Subprocessor{{Name: "AWS"}},
		Documents:     []platform.TrustDocument{{Kind: platform.DocSubprocessors, Visibility: platform.VisGated}},
	})
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})
	var g struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"jane@buyer.example"}`).Body.Bytes(), &g)
	_ = get(t, h, "/v1/trust/t1/doc?token="+tok+"&kind=subprocessors&access="+g.AccessToken)

	reqs, _ := st.ListTrustAccessRequests(context.Background(), "t1")
	if len(reqs[0].Views) != 1 || reqs[0].Views[0].Kind != platform.DocSubprocessors {
		t.Errorf("the open was not logged: %+v", reqs[0].Views)
	}
}

func TestGeneratedDocumentIsWatermarkedForItsRecipient(t *testing.T) {
	// The only control available for an artifact whose whole purpose is to be forwarded.
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{
		Enabled: true, AutoApproveDomains: []string{"buyer.example"},
		Subprocessors: []platform.Subprocessor{{Name: "Amazon Web Services", Purpose: "Hosting"}},
		Documents:     []platform.TrustDocument{{Kind: platform.DocSubprocessors, Visibility: platform.VisGated}},
	})
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})
	var g struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"jane@buyer.example"}`).Body.Bytes(), &g)

	body := get(t, h, "/v1/trust/t1/doc?token="+tok+"&kind=subprocessors&access="+g.AccessToken).Body.String()
	if !strings.Contains(body, "jane@buyer.example") {
		t.Errorf("gated document is not watermarked with its recipient:\n%s", body)
	}
	if !strings.Contains(body, "Amazon Web Services") {
		t.Errorf("the document body is missing:\n%s", body)
	}
}

func TestPublicDocumentIsNotWatermarked(t *testing.T) {
	// Stamping "provided in confidence to an approved reviewer" on something anyone holding the
	// link may read is a false claim about how the document travelled.
	d, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{
		Enabled:       true,
		Subprocessors: []platform.Subprocessor{{Name: "AWS"}},
		Documents:     []platform.TrustDocument{{Kind: platform.DocSubprocessors, Visibility: platform.VisPublic}},
	})
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})
	body := get(t, h, "/v1/trust/t1/doc?token="+tok+"&kind=subprocessors").Body.String()
	if strings.Contains(body, "Provided in confidence") {
		t.Errorf("a public document claims it was issued in confidence:\n%s", body)
	}
}

func TestOwnerCannotPublishAFindingBearingReportThroughTheAPI(t *testing.T) {
	// The refusal has to survive the whole round trip, not just the pure function. This is the
	// one click that would turn the trust page into an attacker's roadmap.
	_, h, st := tcDeps(t)
	seedTrustTenant(t, st, "t1", "Acme", platform.TrustCenterConfig{Enabled: true})
	rec := authed(t, h, "PUT", "/v1/settings/trust-center", "t1",
		`{"enabled":true,"documents":[{"kind":"vapt_report","visibility":"public"}]}`)
	if rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Config      platform.TrustCenterConfig `json:"config"`
		Corrections []trustcenter.Correction   `json:"corrections"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Config.Documents) != 1 || out.Config.Documents[0].Visibility != platform.VisGated {
		t.Fatalf("the VAPT report was stored as %+v", out.Config.Documents)
	}
	if len(out.Corrections) == 0 {
		t.Error("clamped without telling the owner, who now believes the report is public")
	}
	stored, _ := st.GetTenant(context.Background(), "t1")
	if stored.TrustCenter.Documents[0].Visibility != platform.VisGated {
		t.Error("the response was clamped but the stored config was not")
	}
}

func TestAccessRequestsAreRateLimited(t *testing.T) {
	// Unbounded, a script could bury the owner's desk in requests until the real buyer's is
	// invisible — a denial of the feature rather than of the service, and harder to notice.
	d, h, st := tcDeps(t)
	gatedTenant(t, st)
	tok := d.trustTokenFor("t1", platform.TrustCenterConfig{})

	limited := false
	for i := 0; i < trustRequestLimiter.max+2; i++ {
		if post(t, h, "/v1/trust/t1/request?token="+tok, `{"email":"eve@spam.example"}`).Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Errorf("made %d requests without being limited", trustRequestLimiter.max+2)
	}
}

func TestPublicEndpointsRefuseABadShareToken(t *testing.T) {
	// Every public route, not just the page — a gate that covers three of four doors is not one.
	_, h, st := tcDeps(t)
	gatedTenant(t, st)
	for _, c := range []struct {
		method, url string
	}{
		{"GET", "/v1/trust/t1?token=wrong"},
		{"GET", "/v1/trust/t1/doc?token=wrong&kind=subprocessors"},
		{"POST", "/v1/trust/t1/request?token=wrong"},
		{"POST", "/v1/trust/t1/nda?token=wrong"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.url, strings.NewReader(`{"email":"e@x.example"}`)))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: want 404 on a bad share token, got %d", c.method, c.url, rec.Code)
		}
	}
}
