package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/auditreview"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

const arTenant = "t1"
const arTarget = "https://app.example"

func arDeps(t *testing.T, fs ...types.Finding) (Deps, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{
		ID: arTenant,
		Practitioners: []platform.Practitioner{
			{Name: "Ada Auditor", Email: "ada@acme-audit.example", Firm: "Acme Audit LLP", Capacity: platform.CapacityMSP},
		},
	}); err != nil {
		t.Fatal(err)
	}
	u := platform.User{ID: "u1", TenantID: arTenant, Email: "ada@acme-audit.example", Role: platform.RoleOwner}
	if err := st.PutUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSession(ctx, platform.Session{Token: "sess", UserID: u.ID, TenantID: arTenant, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if err := st.PutFinding(ctx, arTenant, f); err != nil {
			t.Fatal(err)
		}
	}
	return Deps{Store: st}, "sess"
}

func arReq(method, path, body, tok string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func arFinding(id, rule, sev string) types.Finding {
	return types.Finding{ID: id, RuleID: rule, Title: rule + " on /x", Endpoint: arTarget + "/x",
		Severity: types.Severity(sev)}
}

// arKey derives the key through crossdetect.DedupKey — the SAME function the handler uses.
//
// Hand-building "rule|endpoint" here is the bug this codebase has already shipped once: the
// suppression source built an issue key by hand, matched nothing for every tenant, and its test
// passed because the fixture hard-coded the same wrong format. Deriving it means the test cannot
// disagree with production about what a key is.
func arKey(f types.Finding) string { return crossdetect.DedupKey(f) }

func getReview(t *testing.T, d Deps, tok string) auditReviewResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handleAuditReview(rec, arReq(http.MethodGet, "/v1/audit-review?target="+arTarget, "", tok), arTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET review: %d %s", rec.Code, rec.Body.String())
	}
	var got auditReviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func decide(t *testing.T, d Deps, tok, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handleAuditDisposition(rec, arReq(http.MethodPost, "/v1/audit-review/disposition", body, tok), arTenant)
	return rec
}

// The review is scoped by LITERAL target match, the same attribution the rest of the platform uses.
// Guessing wider would put another application's findings into this application's certificate.
func TestAuditReview_ScopesToTheApplicationUnderAudit(t *testing.T) {
	other := types.Finding{ID: "f2", RuleID: "nuclei::x", Title: "elsewhere",
		Endpoint: "https://other.example/y", Severity: types.SeverityHigh}
	d, tok := arDeps(t, arFinding("f1", "nuclei::weak-tls", "low"), other)

	got := getReview(t, d, tok)
	if len(got.Items) != 1 || got.Items[0].RuleID != "nuclei::weak-tls" {
		t.Fatalf("scope leaked: %+v", got.Items)
	}
}

// The package's refusals must reach the caller as themselves — each names what is missing from a
// decision that ends up in a signed document.
func TestAuditDisposition_SurfacesTheRefusalsRatherThanAGeneric400(t *testing.T) {
	d, tok := arDeps(t, arFinding("f1", "nuclei::weak-tls", "low"))
	k := arKey(arFinding("f1", "nuclei::weak-tls", "low"))

	for _, c := range []struct{ name, body, want string }{
		{"exclusion with no reason",
			`{"target":"` + arTarget + `","key":"` + k + `","verdict":"exclude"}`, "reason is required"},
		{"reclassification with no severity",
			`{"target":"` + arTarget + `","key":"` + k + `","verdict":"reclassify","reason":"internal only"}`, "needs a severity"},
		{"unknown verdict",
			`{"target":"` + arTarget + `","key":"` + k + `","verdict":"probably"}`, "must be"},
	} {
		rec := decide(t, d, tok, c.body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body.String())
		}
	}
}

// A decision about a finding not in scope would sit in the store forever, invisible and uncounted.
func TestAuditDisposition_RefusesAFindingNotInThisReview(t *testing.T) {
	d, tok := arDeps(t, arFinding("f1", "nuclei::weak-tls", "low"))
	rec := decide(t, d, tok, `{"target":"`+arTarget+`","key":"nuclei::ghost|nowhere","verdict":"include"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d %s", rec.Code, rec.Body.String())
	}
	ds, _ := d.Store.ListAuditDispositions(context.Background(), arTenant)
	if len(ds) != 0 {
		t.Errorf("stored a decision about a finding nobody is auditing: %+v", ds)
	}
}

// The LOWERING direction is taken from the engine's severity, not the caller — it is the direction
// that makes a report look better, so a reader must see it was the reviewer's judgement.
func TestAuditDisposition_RecordsALoweringFromTheEnginesOwnSeverity(t *testing.T) {
	d, tok := arDeps(t, arFinding("f1", "nuclei::xss", "high"))
	k := arKey(arFinding("f1", "nuclei::xss", "high"))
	rec := decide(t, d, tok,
		`{"target":"`+arTarget+`","key":"`+k+`","verdict":"reclassify","severity":"low","reason":"behind SSO, not reachable"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", rec.Code, rec.Body.String())
	}
	ds, _ := d.Store.ListAuditDispositions(context.Background(), arTenant)
	if len(ds) != 1 || !ds[0].Lowered {
		t.Fatalf("a high→low reclassification was not recorded as a lowering: %+v", ds)
	}
	if ds[0].By != "ada@acme-audit.example" {
		t.Errorf("reviewer = %q; it comes from the session", ds[0].By)
	}
}

// THE CENTRAL GATE, through the handler. 409 rather than 400: nothing about the request is
// malformed — the audit is simply not in a state that can be certified.
func TestAuditCertificate_RefusesWhileFindingsAreUndecided(t *testing.T) {
	d, tok := arDeps(t, arFinding("f1", "nuclei::weak-tls", "low"))
	rec := httptest.NewRecorder()
	d.handleAuditCertificate(rec,
		arReq(http.MethodPost, "/v1/audit-review/certificate", `{"target":"`+arTarget+`"}`, tok), arTenant)
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "undecided") {
		t.Errorf("the blocker does not say what is missing: %s", rec.Body.String())
	}
}

// The auditor's FIRM and CAPACITY come from the practitioner roster, never the request — otherwise a
// certificate could claim an independent firm signed it because somebody typed one in.
func TestAuditCertificate_ResolvesCapacityFromTheRosterNotTheRequest(t *testing.T) {
	d, tok := arDeps(t, arFinding("f1", "nuclei::weak-tls", "low"))
	k := arKey(arFinding("f1", "nuclei::weak-tls", "low"))
	if rec := decide(t, d, tok, `{"target":"`+arTarget+`","key":"`+k+`","verdict":"include"}`); rec.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", rec.Code, rec.Body.String())
	}

	rec := httptest.NewRecorder()
	d.handleAuditCertificate(rec, arReq(http.MethodPost, "/v1/audit-review/certificate",
		`{"target":"`+arTarget+`","auditor":"Ada Auditor","firm":"Totally Different Firm"}`, tok), arTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("certificate: %d %s", rec.Code, rec.Body.String())
	}
	var cert auditreview.Certificate
	if err := json.Unmarshal(rec.Body.Bytes(), &cert); err != nil {
		t.Fatal(err)
	}
	if cert.Firm != "Acme Audit LLP" || cert.Capacity != platform.CapacityMSP {
		t.Errorf("firm/capacity = %q/%q — both must come from the roster", cert.Firm, cert.Capacity)
	}
}

// The certificate's untested scope is read from the scan's OWN declared coverage gaps, so it cannot
// say more was covered than was.
func TestAuditCertificate_CarriesTheScansDeclaredCoverageGaps(t *testing.T) {
	gap := types.Finding{
		ID: "c1", RuleID: asset.CoverageRulePrefix + "unauthenticated-only",
		Title:    "Authenticated user roles were not tested — no credentials were supplied",
		Endpoint: arTarget, Severity: types.SeverityInfo,
	}
	d, tok := arDeps(t, arFinding("f1", "nuclei::weak-tls", "low"), gap)

	// The coverage disclosure is itself a finding in scope, so it needs a decision too — which is
	// correct: the reviewer should see what the scan could not check.
	for _, k := range []string{arKey(arFinding("f1", "nuclei::weak-tls", "low")), crossdetect.DedupKey(gap)} {
		if rec := decide(t, d, tok, `{"target":"`+arTarget+`","key":"`+k+`","verdict":"include"}`); rec.Code != http.StatusOK {
			t.Fatalf("decide %s: %d %s", k, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	d.handleAuditCertificate(rec, arReq(http.MethodPost, "/v1/audit-review/certificate",
		`{"target":"`+arTarget+`","auditor":"Ada Auditor"}`, tok), arTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("certificate: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Not covered by this assessment") ||
		!strings.Contains(rec.Body.String(), "Authenticated user roles") {
		t.Errorf("the scan's declared gap is not on the certificate: %s", rec.Body.String())
	}
}

// The prefix is mirrored rather than imported; if asset renames it, this fails loudly instead of the
// certificate silently losing every coverage disclosure.
func TestCoverageRulePrefixMatchesTheAssetLayer(t *testing.T) {
	if coverageRulePrefix != asset.CoverageRulePrefix {
		t.Fatalf("prefix drift: platformapi %q vs asset %q — the certificate would silently stop "+
			"carrying what the scan could not check", coverageRulePrefix, asset.CoverageRulePrefix)
	}
}
