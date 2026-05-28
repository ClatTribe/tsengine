// Package attest manages the persistent ed25519 signing key used to
// attest scan outputs (CLAUDE.md §10). Pre-Phase-5 the engine signed
// with an ephemeral key generated per scan — which made the attestation
// useless to anyone else, since the public key vanished. This package
// gives the engine a stable, on-disk key whose public half can be
// distributed to webappsec / auditors for verification.
package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const pemType = "TSENGINE ED25519 PRIVATE KEY"

// LoadOrCreate returns the ed25519 private key at path. If the file is
// absent, it generates a new key, persists it with 0600 perms (creating
// parent dirs at 0700), and returns it. The returned signer id is
// derived from the public key, so it's stable and identifies which key
// signed a given attestation.
func LoadOrCreate(path string) (ed25519.PrivateKey, string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled key path
	switch {
	case err == nil:
		priv, perr := parsePEM(data)
		if perr != nil {
			return nil, "", fmt.Errorf("attest: parse key %s: %w", path, perr)
		}
		return priv, SignerID(pub(priv)), nil
	case errors.Is(err, os.ErrNotExist):
		return generate(path)
	default:
		return nil, "", fmt.Errorf("attest: read key %s: %w", path, err)
	}
}

func generate(path string) (ed25519.PrivateKey, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("attest: generate key: %w", err)
	}
	if err := persist(path, priv); err != nil {
		return nil, "", err
	}
	return priv, SignerID(pub(priv)), nil
}

func persist(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("attest: marshal key: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("attest: mkdir key dir: %w", err)
		}
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return fmt.Errorf("attest: write key: %w", err)
	}
	return nil
}

func parsePEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 key (%T)", key)
	}
	return priv, nil
}

// SignerID derives a stable identifier from a public key. The same key
// always yields the same id; different keys (almost certainly) differ.
func SignerID(p ed25519.PublicKey) string {
	return "tsengine-key-" + hex.EncodeToString(p)[:16]
}

// PublicKeyHex returns the hex-encoded public half of a private key.
func PublicKeyHex(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(pub(priv))
}

// ParsePublicKeyHex decodes a hex-encoded ed25519 public key.
func ParsePublicKeyHex(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("attest: decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("attest: public key length %d, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// DefaultKeyPath returns the signing key location. Honors
// TSENGINE_SIGNING_KEY; otherwise falls back to the user config dir, or
// a repo-local file as a last resort.
func DefaultKeyPath() string {
	if p := os.Getenv("TSENGINE_SIGNING_KEY"); p != "" {
		return p
	}
	if cfg, err := os.UserConfigDir(); err == nil && cfg != "" {
		return filepath.Join(cfg, "tsengine", "signing.pem")
	}
	return "tsengine-signing.pem"
}

func pub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}
