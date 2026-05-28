package dashboard

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Sign computes the SHA-256 of the scan's canonical JSON form and signs
// it with priv, returning a populated Attestation block ready to set on
// the scan.
//
// signer is a human-readable key identifier (e.g. "tsengine-prod-key-v1");
// it is recorded in the attestation but is NOT used for cryptographic
// operations. now is a clock injection point — tests pin it; production
// callers pass time.Now().UTC().
func Sign(scan types.Scan, signer string, priv ed25519.PrivateKey, now time.Time) (*types.Attestation, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("attestation: invalid private key length %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	if signer == "" {
		return nil, errors.New("attestation: empty signer")
	}
	canon, err := Canonical(scan)
	if err != nil {
		return nil, fmt.Errorf("attestation: canonical: %w", err)
	}
	sum := sha256.Sum256(canon)
	sig := ed25519.Sign(priv, sum[:])
	return &types.Attestation{
		SHA256:    hex.EncodeToString(sum[:]),
		SignedAt:  now.UTC(),
		Signer:    signer,
		Signature: hex.EncodeToString(sig),
	}, nil
}

// Verify checks the attestation on scan against pub. Returns nil if the
// attestation is valid; an error explaining the failure otherwise.
//
// Verify is deliberately permissive about WHICH key — callers pass the
// public key they expect; webappsec would carry a key registry to look
// up by Signer.
func Verify(scan types.Scan, pub ed25519.PublicKey) error {
	if scan.Attestation == nil {
		return errors.New("attestation: missing")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("attestation: invalid public key length %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	canon, err := Canonical(scan)
	if err != nil {
		return fmt.Errorf("attestation: canonical: %w", err)
	}
	sum := sha256.Sum256(canon)
	want := hex.EncodeToString(sum[:])
	if scan.Attestation.SHA256 != want {
		return fmt.Errorf("attestation: hash mismatch (got %s, want %s)", scan.Attestation.SHA256, want)
	}
	sig, err := hex.DecodeString(scan.Attestation.Signature)
	if err != nil {
		return fmt.Errorf("attestation: signature decode: %w", err)
	}
	if !ed25519.Verify(pub, sum[:], sig) {
		return errors.New("attestation: signature verification failed")
	}
	return nil
}
