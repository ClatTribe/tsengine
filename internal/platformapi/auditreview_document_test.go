package platformapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/auditreview"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A reviewed, certifiable audit with a signing key.
func certifiableAudit(t *testing.T) (Deps, string) {
	t.Helper()
	d, tok := arDeps(t, arFinding("f1", "nuclei::weak-tls", "low"))
	k := arKey(arFinding("f1", "nuclei::weak-tls", "low"))
	if rec := decide(t, d, tok, `{"target":"`+arTarget+`","key":"`+k+`","verdict":"include"}`); rec.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", rec.Code, rec.Body.String())
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	d.EvidenceSigner = func() (ed25519.PrivateKey, string, error) { return priv, "test-signer", nil }
	return d, tok
}

func getDoc(d Deps, tok, query string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	d.handleAuditCertificateDocument(rec, arReq(http.MethodGet, "/v1/audit-review/certificate?target="+arTarget+query, "", tok), arTenant)
	return rec
}

func TestAuditCertificateDocument_ServesSignedFormsThatVerify(t *testing.T) {
	d, tok := certifiableAudit(t)

	rec := getDoc(d, tok, "&format=json&not_tested=the+admin+role+had+no+credentials")
	if rec.Code != http.StatusOK {
		t.Fatalf("json: %d %s", rec.Code, rec.Body.String())
	}
	var cert auditreview.Certificate
	if err := json.Unmarshal(rec.Body.Bytes(), &cert); err != nil || cert.Attestation == nil {
		t.Fatalf("signed json must carry the attestation: %v %s", err, rec.Body.String())
	}
	priv, _, _ := d.EvidenceSigner()
	if err := auditreview.Verify(&cert, priv.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("the served document must verify byte-faithfully: %v", err)
	}
	if cert.Firm != "Acme Audit LLP" || cert.Capacity != platform.CapacityMSP || cert.ID == "" {
		t.Errorf("roster-resolved firm/capacity and an id: %+v", cert)
	}
	if !strings.Contains(strings.Join(cert.NotTested, "|"), "admin role") {
		t.Errorf("the auditor's own coverage limit must reach the certificate: %v", cert.NotTested)
	}

	rec = getDoc(d, tok, "&format=md")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "# Safe-to-Host Certificate") || !strings.Contains(rec.Body.String(), "Attestation:") {
		t.Fatalf("md: %d %s", rec.Code, rec.Body.String())
	}
	rec = getDoc(d, tok, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<h1>Safe-to-Host Certificate</h1>") || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("html default: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestAuditCertificateDocument_RefusesAndNeverServesUnsigned(t *testing.T) {
	// Undecided → 409 with blockers, no document.
	d, tok := arDeps(t, arFinding("f1", "nuclei::weak-tls", "low"))
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	d.EvidenceSigner = func() (ed25519.PrivateKey, string, error) { return priv, "s", nil }
	rec := getDoc(d, tok, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "undecided") || strings.Contains(rec.Body.String(), "<h1>") {
		t.Fatalf("undecided: %d %s", rec.Code, rec.Body.String())
	}

	// Certifiable, but no signing key → 501, never an unsigned document. The POST preview still works.
	d, tok = certifiableAudit(t)
	d.EvidenceSigner = nil
	rec = getDoc(d, tok, "&format=md")
	if rec.Code != http.StatusNotImplemented || strings.Contains(rec.Body.String(), "# Safe-to-Host") {
		t.Fatalf("no key: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	d.handleAuditCertificate(rec, arReq(http.MethodPost, "/v1/audit-review/certificate", `{"target":"`+arTarget+`"}`, tok), arTenant)
	if rec.Code != http.StatusOK {
		t.Errorf("the JSON issue path needs no key: %d %s", rec.Code, rec.Body.String())
	}

	// No target → 400.
	rec = httptest.NewRecorder()
	d.handleAuditCertificateDocument(rec, arReq(http.MethodGet, "/v1/audit-review/certificate", "", tok), arTenant)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("no target: %d", rec.Code)
	}
}

// The scope blockers reach the API: a target whose findings arrived with no scan record behind it,
// or whose last scan lost a tool, cannot be certified however complete the review is.
func TestAuditCertificate_RefusesATargetNoScanStandsBehind(t *testing.T) {
	d, tok := certifiableAudit(t)
	ctx := context.Background()
	// Remove the completed engagement the fixture provides → the target is "untested".
	assets, _ := d.Store.ListAssets(ctx, arTenant)
	for _, a := range assets {
		if a.Target == arTarget {
			// A fresh engagement record with a tool failure makes the target PARTIALLY assessed.
			_ = d.Store.PutEngagement(ctx, platform.Engagement{ID: "e-partial", TenantID: arTenant, AssetID: a.ID,
				StartedAt: time.Now(), CompletedAt: time.Now(),
				// A real scan records what it dispatched; coverage reads the failures only beside it.
				ToolsRan:    []string{"httpx", "nuclei"},
				ToolsFailed: []types.ToolFailure{{Tool: "nuclei", Reason: "timeout"}}})
		}
	}
	rec := getDoc(d, tok, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "scope_partial") {
		t.Fatalf("partially assessed target must block: %d %s", rec.Code, rec.Body.String())
	}

	// A target with findings but NO asset at all → untested.
	d2, tok2 := arDeps(t, arFinding("f1", "nuclei::weak-tls", "low"))
	for _, a := range assets {
		_ = d2.Store.PutAsset(ctx, platform.Asset{ID: a.ID, TenantID: arTenant, Type: a.Type, Target: "https://elsewhere.example"})
	}
	k := arKey(arFinding("f1", "nuclei::weak-tls", "low"))
	if rec := decide(t, d2, tok2, `{"target":"`+arTarget+`","key":"`+k+`","verdict":"include"}`); rec.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	d2.handleAuditCertificate(rec, arReq(http.MethodPost, "/v1/audit-review/certificate", `{"target":"`+arTarget+`"}`, tok2), arTenant)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "scope_untested") {
		t.Fatalf("a target no scan stands behind must block the POST too: %d %s", rec.Code, rec.Body.String())
	}
}
