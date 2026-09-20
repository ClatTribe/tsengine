package auditreview

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func issued(t *testing.T) *Certificate {
	t.Helper()
	fs := []types.Finding{finding("f1", "nuclei::weak-tls", "low")}
	k := "nuclei::weak-tls|https://app.example/x"
	r := reviewed(t, fs, include(t, k))
	cert, blockers := Certify(r, CertifyOptions{Auditor: "Ada Auditor", Firm: "Acme Audit LLP", Capacity: "msp", Brand: "Acme Audit LLP",
		NotTested: []string{"the payment flow was out of scope by agreement"}}, now)
	if cert == nil {
		t.Fatalf("fixture must issue: %s", blockerKinds(blockers))
	}
	return cert
}

// THE SCOPE BLOCKERS. A finding list scoped to a target says nothing about whether the target was
// actually scanned: findings can arrive by import, and a scan that lost half its tools still lands
// what the survivors found. Both are the same silence the VAPT report refuses to rate "Clear" on,
// and a certificate is a stronger claim than a rating.
func TestCertify_RefusesAScopeThatWasNotAssessed(t *testing.T) {
	fs := []types.Finding{finding("f1", "nuclei::weak-tls", "low")}
	r := reviewed(t, fs, include(t, "nuclei::weak-tls|https://app.example/x"))

	_, bs := Certify(r, CertifyOptions{Auditor: "Ada Auditor", Untested: []string{"https://app.example"}}, now)
	if !strings.Contains(blockerKinds(bs), "scope_untested") {
		t.Fatalf("a target with no scan behind it must block: %s", blockerKinds(bs))
	}
	_, bs = Certify(r, CertifyOptions{Auditor: "Ada Auditor", PartiallyAssessed: []string{"https://app.example"}}, now)
	if !strings.Contains(blockerKinds(bs), "scope_partial") {
		t.Fatalf("a target scanned with tools missing must block: %s", blockerKinds(bs))
	}
	for _, b := range bs {
		if b.Kind == "scope_partial" && !strings.Contains(b.Detail, "https://app.example") {
			t.Errorf("the blocker names the target: %q", b.Detail)
		}
	}
	// Neither declared → no such blocker, so the existing issuance behaviour is unchanged.
	if cert, bs := Certify(r, CertifyOptions{Auditor: "Ada Auditor"}, now); cert == nil {
		t.Fatalf("no coverage gap declared must still issue: %s", blockerKinds(bs))
	}
}

func TestCertify_StampsIdValidityEngineAndBrand(t *testing.T) {
	c := issued(t)
	if !strings.HasPrefix(c.ID, "STH-") || len(c.ID) != 16 {
		t.Errorf("content-derived id: %q", c.ID)
	}
	if c.ValidUntil != now.Add(certificateValidity) {
		t.Errorf("valid until: %v", c.ValidUntil)
	}
	if c.Engine == "" || c.Brand != "Acme Audit LLP" {
		t.Errorf("engine/brand: %q %q", c.Engine, c.Brand)
	}
	// Same target, auditor and day → same id; a different day → a different certificate.
	again := issued(t)
	if again.ID != c.ID {
		t.Error("re-issuing the same audit on the same day must yield the same number")
	}
	r := reviewed(t, []types.Finding{finding("f1", "nuclei::weak-tls", "low")}, include(t, "nuclei::weak-tls|https://app.example/x"))
	later, _ := Certify(r, CertifyOptions{Auditor: "Ada Auditor"}, now.Add(48*time.Hour))
	if later.ID == c.ID {
		t.Error("a certificate issued on another day is another certificate")
	}
}

func TestRender_CarriesTheStatementVerbatimAndTheLimits(t *testing.T) {
	c := issued(t)
	md := RenderMarkdown(c)
	for _, want := range []string{"# Safe-to-Host Certificate", c.Statement, c.ID, "https://app.example", "Valid until", "payment flow was out of scope", "Firm:** Acme Audit LLP", "excluded with reasons recorded 0", "Open at issue: low 1"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown must carry %q:\n%s", want, md)
		}
	}
	h := RenderHTML(c)
	for _, want := range []string{"<h1>Safe-to-Host Certificate</h1>", "payment flow was out of scope", "Acme Audit LLP"} {
		if !strings.Contains(h, want) {
			t.Errorf("html must carry %q", want)
		}
	}
	// A self-assessment says so and names no firm.
	c.Capacity, c.Firm = "internal", "Whatever Was Typed"
	if md := RenderMarkdown(c); !strings.Contains(md, "self-assessment") || strings.Contains(md, "Whatever Was Typed") {
		t.Errorf("self-assessment rendering: %s", md)
	}
	// User data is escaped in the print form.
	c.Target = `https://app.example/<script>alert(1)</script>`
	if h := RenderHTML(c); strings.Contains(h, "<script>") {
		t.Error("the target must be HTML-escaped")
	}
}

func TestSignAndVerify_DetectTamperingAndRefuseAnUnissuedCertificate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := issued(t)
	if err := Sign(c, "tsengine-prod-key", priv, now); err != nil {
		t.Fatal(err)
	}
	if c.Attestation == nil || c.Attestation.Signer != "tsengine-prod-key" {
		t.Fatalf("attestation: %+v", c.Attestation)
	}
	if err := Verify(c, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(RenderMarkdown(c), c.Attestation.SHA256) {
		t.Error("the rendered certificate carries its digest")
	}
	c.NotTested = nil // quietly widening what was covered, after signing
	if err := Verify(c, pub); err == nil {
		t.Error("removing a coverage limit after signing must fail verification")
	}
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	c2 := issued(t)
	_ = Sign(c2, "other", wrong, now)
	if err := Verify(c2, pub); err == nil {
		t.Error("a certificate signed by another key must not verify")
	}
	// Nothing Certify did not issue can be signed.
	if err := Sign(&Certificate{Target: "https://app.example"}, "s", priv, now); err == nil {
		t.Error("an unissued certificate (no statement, no auditor) must be unsignable")
	}
}
