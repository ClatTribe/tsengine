package platformapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// OAuth `state` integrity.
//
// The state parameter round-trips the initiating tenant through the provider so the UNAUTHENTICATED
// callback (handleConnectCallback) can attribute the new connection. If state were the raw tenant id
// (as it once was), an attacker who knows a victim's tenant id could complete an OAuth flow with
// `state=<victim>` and graft an attacker-controlled provider connection (their own GitHub/Workspace
// token) onto the victim's tenant — cross-tenant connection injection / OAuth login-CSRF. So we sign
// it: a state only verifies if THIS server minted it (at the AUTHENTICATED GET /v1/connect/{kind},
// where the tenant is the real session tenant), and it expires. Keyed by the same platform secret
// (d.Token) the Trust Center token uses, domain-separated so the two token kinds can never be confused.
//
// Scope: this closes the server-side forgery vector — a state cannot be minted for a tenant the caller
// doesn't control. Full login-CSRF defence additionally binds the nonce to the initiating browser
// session via a cookie; that's the documented follow-on. This signed+expiring state is the load-bearing
// half (it's what stops one tenant's connection landing in another's account).

const oauthStateTTL = 15 * time.Minute

func oauthStateMAC(token, msg string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("oauth-state:")) // domain-separation from the Trust Center token (shared key)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignOAuthState returns a signed, expiring OAuth `state` carrying the tenant id, keyed by the platform
// secret. Format "<tenantID>:<unix-exp>:<hex-hmac>" (tenant ids are `ten-<hex>` — no ':' to collide
// with). Exported so the /ui console mints the SAME state the (signed-only) callback verifies — both
// connect entry points stay on the one signed-state contract; a raw tenant id would reopen the
// cross-tenant connection-injection vector this guards.
func SignOAuthState(token, tenantID string) string {
	msg := tenantID + ":" + strconv.FormatInt(time.Now().Add(oauthStateTTL).Unix(), 10)
	return msg + ":" + oauthStateMAC(token, msg)
}

func (d Deps) signOAuthState(tenantID string) string { return SignOAuthState(d.Token, tenantID) }

// verifyOAuthState validates a state token and returns the tenant id it was minted for. ok is false
// for any tampered, malformed, or expired token — the callback trusts the tenant ONLY when the
// signature verifies, never the raw query value (grounding §10). Comparison is constant-time.
func (d Deps) verifyOAuthState(state string) (tenantID string, ok bool) {
	i := strings.LastIndex(state, ":")
	if i < 0 {
		return "", false
	}
	msg, sig := state[:i], state[i+1:]
	if !hmac.Equal([]byte(sig), []byte(oauthStateMAC(d.Token, msg))) {
		return "", false
	}
	j := strings.LastIndex(msg, ":")
	if j < 0 {
		return "", false
	}
	tenantID, expStr := msg[:j], msg[j+1:]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || tenantID == "" || time.Now().Unix() > exp {
		return "", false
	}
	return tenantID, true
}
