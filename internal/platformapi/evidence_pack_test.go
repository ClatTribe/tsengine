package platformapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
)

// ADR 0031 D2b acceptance: the signed evidence pack is SERVED and its attestation VERIFIES — and
// an unsigned artifact is never served from the signed endpoint.

func TestEvidencePack_SignsAndVerifies(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, GRC: &grc.GRC{Store: st}, Token: "tok"}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d.EvidenceSigner = func() (ed25519.PrivateKey, string, error) { return priv, "test-signer", nil }

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/compliance/soc2/evidence-pack", nil)
	req.SetPathValue("framework", "soc2")
	d.handleEvidencePack(rec, req, "t1")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var pack grc.EvidencePack
	if err := json.Unmarshal(rec.Body.Bytes(), &pack); err != nil {
		t.Fatal(err)
	}
	if pack.Attestation == nil || pack.Attestation.Signature == "" {
		t.Fatal("served pack carries no attestation")
	}
	if pack.Attestation.Signer != "test-signer" {
		t.Errorf("signer id = %q", pack.Attestation.Signer)
	}
	if err := grc.Verify(&pack, pub); err != nil {
		t.Errorf("served pack must verify against the signing public key: %v", err)
	}
}

func TestEvidencePack_NoSignerIs501NeverUnsigned(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, GRC: &grc.GRC{Store: st}, Token: "tok"} // EvidenceSigner deliberately nil
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/compliance/soc2/evidence-pack", nil)
	req.SetPathValue("framework", "soc2")
	d.handleEvidencePack(rec, req, "t1")

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("without a signer the endpoint must 501, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "signing") {
		t.Errorf("the refusal must say why: %s", rec.Body.String())
	}
}

func TestEvidencePack_UnknownFramework404(t *testing.T) {
	st := store.NewMemory()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := Deps{Store: st, GRC: &grc.GRC{Store: st}, Token: "tok",
		EvidenceSigner: func() (ed25519.PrivateKey, string, error) { return priv, "s", nil }}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/compliance/not-a-framework/evidence-pack", nil)
	req.SetPathValue("framework", "not-a-framework")
	d.handleEvidencePack(rec, req, "t1")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown framework must 404, got %d", rec.Code)
	}
}
