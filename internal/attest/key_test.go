package attest

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreate_GeneratesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "signing.pem")
	priv, signer, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("bad key size %d", len(priv))
	}
	if !strings.HasPrefix(signer, "tsengine-key-") {
		t.Errorf("signer id: %q", signer)
	}
	// File must exist with 0600 perms.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key not persisted: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key perms: got %o, want 600", info.Mode().Perm())
	}
}

func TestLoadOrCreate_RoundTripStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")
	priv1, signer1, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	priv2, signer2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !priv1.Equal(priv2) {
		t.Error("loaded key differs from created key")
	}
	if signer1 != signer2 {
		t.Errorf("signer id unstable: %q vs %q", signer1, signer2)
	}
}

func TestSignerID_StableDifferentKeysDiffer(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	if SignerID(pub1) == SignerID(pub2) {
		t.Error("distinct keys produced same signer id")
	}
	// Determinism: two distinct calls on the same key produce the same id.
	id1, id2 := SignerID(pub1), SignerID(pub1)
	if id1 != id2 {
		t.Error("signer id not deterministic")
	}
}

func TestPublicKeyHex_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")
	priv, _, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	hexKey := PublicKeyHex(priv)
	parsed, err := ParsePublicKeyHex(hexKey)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Equal(priv.Public().(ed25519.PublicKey)) {
		t.Error("pubkey hex round-trip mismatch")
	}
}

func TestParsePublicKeyHex_RejectsBadLength(t *testing.T) {
	if _, err := ParsePublicKeyHex("abcd"); err == nil {
		t.Error("expected error for short key")
	}
	if _, err := ParsePublicKeyHex("nothex"); err == nil {
		t.Error("expected error for non-hex")
	}
}

func TestLoadOrCreate_RejectsGarbageFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.pem")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(path); err == nil {
		t.Error("expected error for garbage key file")
	}
}

func TestDefaultKeyPath_HonorsEnv(t *testing.T) {
	t.Setenv("TSENGINE_SIGNING_KEY", "/custom/path.pem")
	if got := DefaultKeyPath(); got != "/custom/path.pem" {
		t.Errorf("DefaultKeyPath: got %q", got)
	}
}
