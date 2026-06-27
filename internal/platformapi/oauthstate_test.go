package platformapi

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// A legitimately-minted state round-trips back to its tenant.
func TestOAuthState_RoundTrip(t *testing.T) {
	d := Deps{Token: "platform-secret"}
	got, ok := d.verifyOAuthState(d.signOAuthState("ten-abc123"))
	if !ok || got != "ten-abc123" {
		t.Fatalf("round-trip failed: got %q ok=%v", got, ok)
	}
}

// THE security property: an attacker who knows a victim's tenant id CANNOT forge a state for it
// (no platform secret) → the callback rejects it → no cross-tenant connection injection.
func TestOAuthState_ForgedTenantRejected(t *testing.T) {
	server := Deps{Token: "platform-secret"}
	attacker := Deps{Token: "attacker-guess"} // attacker can't know the real key

	// 1. A raw tenant id (the old behaviour) must not verify.
	if _, ok := server.verifyOAuthState("ten-victim"); ok {
		t.Fatal("SECURITY: a raw, unsigned tenant id verified — cross-tenant injection is possible")
	}
	// 2. A state the attacker signs with a wrong key must not verify against the server.
	if _, ok := server.verifyOAuthState(attacker.signOAuthState("ten-victim")); ok {
		t.Fatal("SECURITY: an attacker-signed state verified — the signing key is not load-bearing")
	}
	// 3. Tampering the tenant in a real token (keeping the old signature) must not verify.
	good := server.signOAuthState("ten-attacker")
	tampered := strings.Replace(good, "ten-attacker", "ten-victim", 1)
	if _, ok := server.verifyOAuthState(tampered); ok {
		t.Fatal("SECURITY: a tampered tenant verified — the MAC does not cover the tenant id")
	}
}

// An expired state is rejected (bounds the CSRF window).
func TestOAuthState_Expired(t *testing.T) {
	d := Deps{Token: "platform-secret"}
	// hand-mint a state whose exp is in the past, signed correctly.
	msg := "ten-abc:" + strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
	expired := msg + ":" + d.oauthStateMAC(msg)
	if _, ok := d.verifyOAuthState(expired); ok {
		t.Fatal("an expired state verified")
	}
}

// Malformed inputs never panic and never verify.
func TestOAuthState_Malformed(t *testing.T) {
	d := Deps{Token: "platform-secret"}
	for _, s := range []string{"", "nope", "a:b", "ten-x:notanumber:deadbeef", ":"} {
		if _, ok := d.verifyOAuthState(s); ok {
			t.Fatalf("malformed state %q verified", s)
		}
	}
}
