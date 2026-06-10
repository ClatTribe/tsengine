// Package secret vaults the OAuth tokens the platform holds on behalf of tenants
// (docs/autonomous-team.md §3.1, open decision #3). A connection never stores its
// token inline — Connection.SecretRef holds a sealed reference the Vault can open.
//
// The MVP Vault is dependency-free AES-256-GCM with a key from the environment (the
// "KMS-envelope for the MVP" decision); a real cloud-KMS Vault slots in behind the
// same interface. Plain (no encryption) exists for local dev and is explicit about it.
package secret

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// encPrefix tags an AES-GCM-sealed reference so Open knows to decrypt it (and so a
// plaintext value can pass through during a migration).
const encPrefix = "enc:"

// Vault seals a secret into an opaque reference and opens it back. Implementations
// MUST be safe to call concurrently.
type Vault interface {
	Seal(plaintext string) (ref string, err error)
	Open(ref string) (plaintext string, err error)
}

// --- AES-256-GCM vault ---

// AESGCM encrypts secrets at rest with a 32-byte key. The sealed ref is
// "enc:" + base64(nonce || ciphertext). A value without the enc: prefix is treated as
// already-plaintext on Open (so dev/unsealed connections still work).
type AESGCM struct{ aead cipher.AEAD }

// NewAESGCM builds the vault from a 32-byte key.
func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secret: AES key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESGCM{aead: aead}, nil
}

func (v *AESGCM) Seal(plaintext string) (string, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := v.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

func (v *AESGCM) Open(ref string) (string, error) {
	if !strings.HasPrefix(ref, encPrefix) {
		return ref, nil // unsealed plaintext (dev / pre-migration)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ref, encPrefix))
	if err != nil {
		return "", fmt.Errorf("secret: decode: %w", err)
	}
	ns := v.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("secret: ciphertext too short")
	}
	pt, err := v.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("secret: open (wrong key or tampered): %w", err)
	}
	return string(pt), nil
}

// --- Plain (dev) vault ---

// Plain stores secrets without encryption. Seal is the identity; Open refuses an
// enc:-prefixed value (it has no key) so a misconfigured prod can't silently leak a
// failure as success.
type Plain struct{}

func (Plain) Seal(plaintext string) (string, error) { return plaintext, nil }
func (Plain) Open(ref string) (string, error) {
	if strings.HasPrefix(ref, encPrefix) {
		return "", errors.New("secret: sealed ref but no key configured (set TSENGINE_SECRET_KEY)")
	}
	return ref, nil
}

// FromEnv returns an AES-GCM vault when TSENGINE_SECRET_KEY (base64-encoded 32 bytes)
// is set, else a Plain vault. The bool reports whether encryption is on.
func FromEnv() (Vault, bool, error) {
	b64 := os.Getenv("TSENGINE_SECRET_KEY")
	if b64 == "" {
		return Plain{}, false, nil
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, false, fmt.Errorf("secret: TSENGINE_SECRET_KEY not valid base64: %w", err)
	}
	v, err := NewAESGCM(key)
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

// --- runner.Tokens adapter ---

// Tokens resolves a connection's token by opening its sealed SecretRef. It satisfies
// runner.Tokens.
type Tokens struct{ V Vault }

// Resolve opens the connection's vaulted token.
func (t Tokens) Resolve(_ context.Context, c platform.Connection) (string, error) {
	if t.V == nil {
		return "", errors.New("secret: no vault configured")
	}
	return t.V.Open(c.SecretRef)
}
