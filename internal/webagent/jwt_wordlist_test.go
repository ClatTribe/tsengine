package webagent

import (
	"strings"
	"testing"
)

// TestCrackJWT_CommonPasswordSecret: jwt_crack must now also crack a JWT whose HMAC secret is a common
// password reachable only via crack_hash's broader wordlist + mangling — NOT one of the 35 JWT-tutorial
// secrets. Grounded: a JWT secret is frequently just a common word, and jwt_crack previously tried only
// its own narrow list. "welcome2024" = commonPasswords["welcome"] + mangleSuffixes["2024"].
func TestCrackJWT_CommonPasswordSecret(t *testing.T) {
	// sanity: the secret must NOT be in the JWT-specific list (else this wouldn't prove the unification)
	for _, s := range jwtWeakSecrets {
		if s == "welcome2024" {
			t.Fatal("test secret is already in jwtWeakSecrets; pick one that isn't")
		}
	}
	token := makeHS256(t, "welcome2024", map[string]any{"sub": "1", "role": "user"})
	res := crackJWT(token, map[string]any{"sub": "2", "role": "admin"})
	if !res.Cracked || res.Secret != "welcome2024" {
		t.Fatalf("common-password JWT secret not cracked via the unified wordlist: %+v", res)
	}
	if res.Forged == "" || !strings.Contains(crackJWT(res.Forged, nil).Payload, `"2"`) {
		t.Errorf("forged token missing the escalated sub claim: %q", res.Forged)
	}
}
