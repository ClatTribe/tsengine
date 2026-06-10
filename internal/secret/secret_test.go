package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAESGCM_SealOpenRoundTrip(t *testing.T) {
	v, err := NewAESGCM(key(t))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := v.Seal("ghp_secrettoken")
	if err != nil {
		t.Fatal(err)
	}
	// the token must NOT appear in the sealed ref
	if strings.Contains(ref, "ghp_secrettoken") {
		t.Fatal("sealed ref leaked the plaintext token")
	}
	if !strings.HasPrefix(ref, encPrefix) {
		t.Errorf("sealed ref should be enc:-tagged, got %q", ref)
	}
	got, err := v.Open(ref)
	if err != nil || got != "ghp_secrettoken" {
		t.Errorf("round-trip failed: got %q err %v", got, err)
	}
	// two seals of the same secret differ (random nonce)
	ref2, _ := v.Seal("ghp_secrettoken")
	if ref == ref2 {
		t.Error("seal should be non-deterministic (random nonce)")
	}
}

func TestAESGCM_WrongKeyFails(t *testing.T) {
	v1, _ := NewAESGCM(key(t))
	v2, _ := NewAESGCM(key(t)) // different key
	ref, _ := v1.Seal("tok")
	if _, err := v2.Open(ref); err == nil {
		t.Fatal("opening with the wrong key must fail")
	}
}

func TestAESGCM_TamperFails(t *testing.T) {
	k := key(t)
	v, _ := NewAESGCM(k)
	ref, _ := v.Seal("tok")
	// flip a byte in the base64 body
	b := []byte(ref)
	b[len(b)-2] ^= 0x01
	if _, err := v.Open(string(b)); err == nil {
		t.Fatal("a tampered ciphertext must fail to open (GCM auth)")
	}
}

func TestAESGCM_PlaintextPassthrough(t *testing.T) {
	v, _ := NewAESGCM(key(t))
	// an unsealed value (no enc: prefix) opens as itself — supports migration/dev
	if got, _ := v.Open("rawtoken"); got != "rawtoken" {
		t.Errorf("plaintext passthrough failed: %q", got)
	}
}

func TestPlain_RefusesSealedRef(t *testing.T) {
	p := Plain{}
	if got, _ := p.Seal("tok"); got != "tok" {
		t.Errorf("plain seal is identity, got %q", got)
	}
	if _, err := p.Open(encPrefix + "abc"); err == nil {
		t.Error("Plain must refuse a sealed ref rather than silently fail")
	}
}

func TestKeySizeValidated(t *testing.T) {
	if _, err := NewAESGCM(make([]byte, 16)); err == nil {
		t.Error("a 16-byte key should be rejected (want 32)")
	}
}

func TestTokensAdapter(t *testing.T) {
	v, _ := NewAESGCM(key(t))
	ref, _ := v.Seal("the-token")
	tk := Tokens{V: v}
	got, err := tk.Resolve(context.Background(), platform.Connection{SecretRef: ref})
	if err != nil || got != "the-token" {
		t.Errorf("Tokens.Resolve failed: %q %v", got, err)
	}
	// nil vault errors rather than returning a bogus token
	if _, err := (Tokens{}).Resolve(context.Background(), platform.Connection{}); err == nil {
		t.Error("Tokens with no vault should error")
	}
}

func TestFromEnv_DefaultsToPlain(t *testing.T) {
	t.Setenv("TSENGINE_SECRET_KEY", "")
	v, enc, err := FromEnv()
	if err != nil || enc {
		t.Fatalf("no key → Plain, got enc=%v err=%v", enc, err)
	}
	if _, ok := v.(Plain); !ok {
		t.Errorf("want Plain vault, got %T", v)
	}
}

func TestFromEnv_BadKeyErrors(t *testing.T) {
	t.Setenv("TSENGINE_SECRET_KEY", "not-base64!!!")
	if _, _, err := FromEnv(); err == nil {
		t.Error("an invalid base64 key should error, not silently fall back")
	}
}

// ensure key bytes aren't accidentally reused as nonce, etc. (sanity)
func TestNonceUnique(t *testing.T) {
	v, _ := NewAESGCM(key(t))
	r1, _ := v.Seal("x")
	r2, _ := v.Seal("x")
	if bytes.Equal([]byte(r1), []byte(r2)) {
		t.Error("nonce reuse: identical seals")
	}
}
