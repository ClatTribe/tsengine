package webagent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// makeHS256 mints a real HS256 JWT signed with secret, carrying claims — the fixture the crack tests
// run against (no external dependency).
func makeHS256(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	hdrB, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payB, _ := json.Marshal(claims)
	seg := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	in := seg(hdrB) + "." + seg(payB)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TestCrackJWT_WeakSecretAndForge: a token signed with a weak secret cracks, and the forged token
// carries the attacker claim AND still verifies under the cracked secret (a usable impersonation token).
func TestCrackJWT_WeakSecretAndForge(t *testing.T) {
	token := makeHS256(t, "secret", map[string]any{"user": "guest", "role": "user"})
	res := crackJWT(token, map[string]any{"user": "admin", "role": "admin"})
	if !res.Cracked || res.Secret != "secret" {
		t.Fatalf("weak secret not cracked: %+v", res)
	}
	if res.Forged == "" {
		t.Fatal("no forged token produced despite a crack + claims")
	}
	// the forged token must verify under the cracked secret AND carry the escalated claim
	f := crackJWT(res.Forged, nil)
	if !f.Cracked {
		t.Errorf("forged token does not verify under the cracked secret: %+v", f)
	}
	if !strings.Contains(f.Payload, `"admin"`) {
		t.Errorf("forged token missing the escalated claim: %s", f.Payload)
	}
}

// TestCrackJWT_AlgNone: the classic unsigned bypass is detected and forged without any secret.
func TestCrackJWT_AlgNone(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"user":"guest"}`))
	token := hdr + "." + pay + "."
	res := crackJWT(token, map[string]any{"user": "admin"})
	if !res.AlgNone {
		t.Fatalf("alg:none not detected: %+v", res)
	}
	if res.Forged == "" || !strings.HasSuffix(res.Forged, ".") {
		t.Errorf("alg:none forge should be an unsigned token ending in '.': %q", res.Forged)
	}
	if !strings.Contains(crackJWT(res.Forged, nil).Payload, `"admin"`) {
		t.Errorf("alg:none forge missing the escalated claim")
	}
}

// TestCrackJWT_StrongSecretNotCracked is the no-false-positive guard (§10): a strong secret must NOT
// be reported cracked, and the alg is still parsed for the agent.
func TestCrackJWT_StrongSecretNotCracked(t *testing.T) {
	token := makeHS256(t, "a-very-long-random-strong-secret-9f8a7b6c5d4e3f2a1b", map[string]any{"user": "guest"})
	res := crackJWT(token, map[string]any{"user": "admin"})
	if res.Cracked {
		t.Errorf("strong secret wrongly reported cracked (false positive): secret=%q", res.Secret)
	}
	if res.Forged != "" {
		t.Errorf("a token was forged without cracking the secret (would not verify): %q", res.Forged)
	}
	if res.Alg != "HS256" {
		t.Errorf("alg not parsed for a strong-secret token: %+v", res)
	}
}

// TestTJWT_ToolSurface drives the tool handler end to end (the observation the agent reads).
func TestTJWT_ToolSurface(t *testing.T) {
	token := makeHS256(t, "changeme", map[string]any{"user": "guest"})
	out := tJWT(&Context{}, map[string]any{"token": token, "claims": map[string]any{"user": "admin"}})
	if !strings.Contains(out, "CRACKED") || !strings.Contains(out, "changeme") {
		t.Errorf("tool did not report the crack: %s", out)
	}
	if !strings.Contains(out, "FORGED TOKEN") {
		t.Errorf("tool did not surface the forged token: %s", out)
	}
	if got := tJWT(&Context{}, map[string]any{}); !strings.Contains(got, "token is required") {
		t.Errorf("missing-token error not returned: %s", got)
	}
}
