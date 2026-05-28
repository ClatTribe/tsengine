package dashboard

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func mustKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func TestSign_VerifyRoundTrip(t *testing.T) {
	pub, priv := mustKeys(t)
	scan := sampleScan()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	att, err := Sign(scan, "test-signer", priv, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if att.Signer != "test-signer" {
		t.Errorf("Signer: got %q, want %q", att.Signer, "test-signer")
	}
	if !att.SignedAt.Equal(now) {
		t.Errorf("SignedAt: got %v, want %v", att.SignedAt, now)
	}

	scan.Attestation = att
	if err := Verify(scan, pub); err != nil {
		t.Errorf("Verify on freshly-signed scan: %v", err)
	}
}

func TestVerify_DetectsTampering(t *testing.T) {
	pub, priv := mustKeys(t)
	scan := sampleScan()

	att, err := Sign(scan, "test-signer", priv, time.Now().UTC())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	scan.Attestation = att

	// Mutate a finding — the canonical hash will change.
	scan.FindingsRaw[0].Severity = types.SeverityCritical

	err = Verify(scan, pub)
	if err == nil {
		t.Fatal("Verify on tampered scan returned nil error")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("expected hash mismatch error; got %v", err)
	}
}

func TestVerify_RejectsWrongKey(t *testing.T) {
	_, priv := mustKeys(t)
	wrongPub, _ := mustKeys(t)
	scan := sampleScan()

	att, err := Sign(scan, "test-signer", priv, time.Now().UTC())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	scan.Attestation = att

	err = Verify(scan, wrongPub)
	if err == nil {
		t.Fatal("Verify with wrong key returned nil error")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("expected signature verification error; got %v", err)
	}
}

func TestVerify_MissingAttestation(t *testing.T) {
	pub, _ := mustKeys(t)
	scan := sampleScan()
	// No attestation set.
	err := Verify(scan, pub)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("expected missing-attestation error; got %v", err)
	}
}

func TestSign_RejectsEmptySigner(t *testing.T) {
	_, priv := mustKeys(t)
	_, err := Sign(sampleScan(), "", priv, time.Now())
	if err == nil || !strings.Contains(err.Error(), "empty signer") {
		t.Errorf("expected empty signer error; got %v", err)
	}
}

func TestSign_RejectsBadKeyLength(t *testing.T) {
	scan := sampleScan()
	_, err := Sign(scan, "signer", ed25519.PrivateKey{0x01}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "invalid private key length") {
		t.Errorf("expected key-length error; got %v", err)
	}
}

func TestSignVerify_DeterministicAcrossSliceOrdering(t *testing.T) {
	// The reproducibility invariant requires that two equivalent scans
	// produce the same hash — so signing one and verifying via the other
	// must work.
	pub, priv := mustKeys(t)

	a := sampleScan()
	b := sampleScan()
	b.FindingsRaw[0], b.FindingsRaw[1] = b.FindingsRaw[1], b.FindingsRaw[0]

	att, err := Sign(a, "test-signer", priv, time.Now().UTC())
	if err != nil {
		t.Fatalf("Sign(a): %v", err)
	}
	b.Attestation = att
	if err := Verify(b, pub); err != nil {
		t.Errorf("Verify(b) with attestation of a: %v", err)
	}
}
