package grc

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// T7 — REPORT. The task is "evidence an auditor accepts", and the property that makes evidence
// auditor-grade is not that it is signed. It is that TAMPERING BREAKS THE SIGNATURE.
//
// A pack that signs but does not detect alteration is worse than an unsigned one: it carries the
// authority of a signature with none of the guarantee. T7 was shipped and benchmarked only by unit
// tests of its parts; nothing exercised sign → verify → tamper → reject as one flow.

func signedPack(t *testing.T) (*EvidencePack, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	p := &EvidencePack{
		TenantID: "t1", Framework: "soc2",
		GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Controls: []platform.ControlState{
			{TenantID: "t1", Framework: "soc2", ControlID: "CC6.1", State: platform.ControlGap},
			{TenantID: "t1", Framework: "soc2", ControlID: "CC6.6", State: platform.ControlMet},
		},
		GapCount: 1,
	}
	if err := Sign(p, "tsengine-test-key", priv, p.GeneratedAt); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return p, pub
}

func TestT7_SignedEvidenceVerifies(t *testing.T) {
	p, pub := signedPack(t)
	if p.Attestation == nil || p.Attestation.Signature == "" {
		t.Fatal("T7 BROKEN: the pack carries no attestation")
	}
	if err := Verify(p, pub); err != nil {
		t.Fatalf("T7 BROKEN: a freshly signed pack does not verify: %v", err)
	}
}

// THE property. An auditor's trust rests entirely on this.
func TestT7_TamperingBreaksTheSignature(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*EvidencePack)
	}{
		{"a gap is flipped to met", func(p *EvidencePack) { p.Controls[0].State = platform.ControlMet }},
		{"the gap count is edited", func(p *EvidencePack) { p.GapCount = 0 }},
		{"a control is removed", func(p *EvidencePack) { p.Controls = p.Controls[:1] }},
		{"the tenant is swapped", func(p *EvidencePack) { p.TenantID = "someone-else" }},
		{"the framework is swapped", func(p *EvidencePack) { p.Framework = "pci" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, pub := signedPack(t)
			tc.mutate(p)
			if err := Verify(p, pub); err == nil {
				t.Errorf("T7 BROKEN: %s went UNDETECTED — the signature carries authority without "+
					"guarantee, which is worse than no signature at all", tc.name)
			}
		})
	}
}

// A pack signed by one key must not verify under another, or a signature proves nothing about WHO
// produced the evidence.
func TestT7_WrongKeyIsRejected(t *testing.T) {
	p, _ := signedPack(t)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(p, otherPub); err == nil {
		t.Error("T7 BROKEN: the pack verified under a key that did not sign it")
	}
}

// An unsigned pack must be rejected outright rather than treated as trivially valid.
func TestT7_UnsignedPackIsRejected(t *testing.T) {
	_, pub, err := func() (ed25519.PrivateKey, ed25519.PublicKey, error) {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		return priv, pub, e
	}()
	if err != nil {
		t.Fatal(err)
	}
	p := &EvidencePack{TenantID: "t1", Framework: "soc2"}
	if err := Verify(p, pub); err == nil {
		t.Error("T7 BROKEN: an unsigned pack verified — absence of a signature must never read as valid")
	}
}
