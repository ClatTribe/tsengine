package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeIdP struct {
	srv  *httptest.Server
	rsa  *rsa.PrivateKey
	ec   *ecdsa.PrivateKey
	mu   sync.Mutex
	kids []string // kids currently published
	iss  string   // issuer the metadata claims (defaults to the server URL)
	tok  string   // id_token returned by the token endpoint
	seen url_values
}

type url_values map[string]string

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &fakeIdP{rsa: rk, ec: ek, kids: []string{"r1", "e1"}}
	mux := http.NewServeMux()
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := f.iss
		if iss == "" {
			iss = f.srv.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": iss, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b := base64.RawURLEncoding
		var keys []map[string]string
		for _, kid := range f.kids {
			switch kid[0] {
			case 'r':
				keys = append(keys, map[string]string{"kty": "RSA", "kid": kid, "use": "sig",
					"n": b.EncodeToString(f.rsa.N.Bytes()), "e": b.EncodeToString([]byte{1, 0, 1})})
			case 'e':
				keys = append(keys, map[string]string{"kty": "EC", "kid": kid, "crv": "P-256",
					"x": b.EncodeToString(pad32(f.ec.X.Bytes())), "y": b.EncodeToString(pad32(f.ec.Y.Bytes()))})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user, pass, _ := r.BasicAuth()
		f.seen = url_values{"code": r.Form.Get("code"), "verifier": r.Form.Get("code_verifier"), "client": user, "secret": pass}
		if r.Form.Get("code") != "good-code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": f.tok})
	})
	return f
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func seg(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (f *fakeIdP) sign(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	head := seg(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	body := seg(claims)
	digest := sha256.Sum256([]byte(head + "." + body))
	var sig []byte
	switch alg {
	case "RS256":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, f.rsa, crypto.SHA256, digest[:])
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, f.ec, digest[:])
		sig = append(pad32(r.Bytes()), pad32(s.Bytes())...)
	}
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIdP) claims(now time.Time) map[string]any {
	return map[string]any{"iss": f.srv.URL, "aud": "client-1", "sub": "user-123", "email": "Ada@Acme.example",
		"email_verified": true, "nonce": "n-1", "exp": now.Add(5 * time.Minute).Unix(), "amr": []string{"pwd", "mfa"}}
}

func discover(t *testing.T, f *fakeIdP) *Provider {
	t.Helper()
	p, err := Discover(context.Background(), f.srv.Client(), f.srv.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	return p
}

func TestVerify_AcceptsAValidTokenInBothAlgorithms(t *testing.T) {
	f := newIdP(t)
	p := discover(t, f)
	now := time.Now()
	for alg, kid := range map[string]string{"RS256": "r1", "ES256": "e1"} {
		c, err := p.Verify(context.Background(), f.sign(t, alg, kid, f.claims(now)), "client-1", "n-1", now)
		if err != nil {
			t.Fatalf("%s: a valid token was refused: %v", alg, err)
		}
		if c.Email != "ada@acme.example" || !c.EmailVerified || c.Subject != "user-123" || !c.MFA() {
			t.Errorf("%s: claims = %+v", alg, c)
		}
	}
}

// Every refusal, each a way a forged or misdirected token would otherwise sign someone in.
func TestVerify_RefusesEveryBadToken(t *testing.T) {
	f := newIdP(t)
	p := discover(t, f)
	now := time.Now()
	good := f.claims(now)
	with := func(k string, v any) map[string]any {
		c := map[string]any{}
		for kk, vv := range good {
			c[kk] = vv
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	// HS256 forged with the provider's public key as the HMAC secret — the classic confusion attack.
	hsHead := seg(map[string]string{"alg": "HS256", "kid": "r1"})
	hsBody := seg(good)
	mac := hmac.New(sha256.New, f.rsa.N.Bytes())
	mac.Write([]byte(hsHead + "." + hsBody))
	hs := hsHead + "." + hsBody + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	none := seg(map[string]string{"alg": "none"}) + "." + seg(good) + "."

	valid := f.sign(t, "RS256", "r1", good)
	parts := strings.Split(valid, ".")
	tampered := parts[0] + "." + seg(with("email", "mallory@evil.example")) + "." + parts[2]

	cases := map[string]string{
		"alg none":            none,
		"HS256 key confusion": hs,
		"tampered payload":    tampered,
		"wrong issuer":        f.sign(t, "RS256", "r1", with("iss", "https://evil.example")),
		"wrong audience":      f.sign(t, "RS256", "r1", with("aud", "someone-else")),
		"multi-aud, no azp":   f.sign(t, "RS256", "r1", with("aud", []string{"client-1", "other"})),
		"expired":             f.sign(t, "RS256", "r1", with("exp", now.Add(-10*time.Minute).Unix())),
		"no exp":              f.sign(t, "RS256", "r1", with("exp", nil)),
		"not yet valid":       f.sign(t, "RS256", "r1", with("nbf", now.Add(10*time.Minute).Unix())),
		"wrong nonce":         f.sign(t, "RS256", "r1", with("nonce", "n-other")),
		"no subject":          f.sign(t, "RS256", "r1", with("sub", nil)),
		"unknown kid":         f.sign(t, "RS256", "r9", good),
		"not a JWS":           "abc.def",
	}
	for name, tok := range cases {
		if _, err := p.Verify(context.Background(), tok, "client-1", "n-1", now); err == nil {
			t.Errorf("%s: token was ACCEPTED", name)
		}
	}
	// And an empty expected nonce never matches, even a token with no nonce.
	if _, err := p.Verify(context.Background(), f.sign(t, "RS256", "r1", with("nonce", nil)), "client-1", "", now); err == nil {
		t.Error("a token was accepted against an empty expected nonce")
	}
	// Multi-audience IS accepted when azp names us.
	c := with("aud", []string{"client-1", "other"})
	c["azp"] = "client-1"
	if _, err := p.Verify(context.Background(), f.sign(t, "RS256", "r1", c), "client-1", "n-1", now); err != nil {
		t.Errorf("a multi-audience token authorized to us was refused: %v", err)
	}
}

// Providers rotate keys; an unseen kid is fetched once.
func TestVerify_RefetchesKeysOnRotation(t *testing.T) {
	f := newIdP(t)
	p := discover(t, f)
	now := time.Now()
	if _, err := p.Verify(context.Background(), f.sign(t, "RS256", "r1", f.claims(now)), "client-1", "n-1", now); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.kids = []string{"r2", "e1"} // rotated: same key material published under a new kid
	f.mu.Unlock()
	if _, err := p.Verify(context.Background(), f.sign(t, "RS256", "r2", f.claims(now)), "client-1", "n-1", now); err != nil {
		t.Errorf("a rotated key was not picked up: %v", err)
	}
}

func TestEmailVerifiedAsString(t *testing.T) {
	f := newIdP(t)
	p := discover(t, f)
	now := time.Now()
	c := f.claims(now)
	c["email_verified"] = "true"
	got, err := p.Verify(context.Background(), f.sign(t, "RS256", "r1", c), "client-1", "n-1", now)
	if err != nil || !got.EmailVerified {
		t.Errorf("email_verified as a string: %+v %v", got, err)
	}
	c["email_verified"] = "false"
	got, _ = p.Verify(context.Background(), f.sign(t, "RS256", "r1", c), "client-1", "n-1", now)
	if got.EmailVerified {
		t.Error(`email_verified "false" read as true`)
	}
}

func TestDiscover_RefusesMismatchAndPlainHTTP(t *testing.T) {
	f := newIdP(t)
	f.iss = "https://someone-else.example"
	if _, err := Discover(context.Background(), f.srv.Client(), f.srv.URL); err == nil {
		t.Error("discovery accepted metadata naming a different issuer")
	}
	if _, err := Discover(context.Background(), http.DefaultClient, "http://idp.example"); err == nil {
		t.Error("discovery accepted a plain-http issuer")
	}
}

func TestExchangeAndAuthURL(t *testing.T) {
	f := newIdP(t)
	p := discover(t, f)
	f.tok = "the-id-token"
	got, err := p.Exchange(context.Background(), "client-1", "s3cret", "https://app.example/cb", "good-code", "verifier-1")
	if err != nil || got != "the-id-token" {
		t.Fatalf("exchange: %q %v", got, err)
	}
	if f.seen["verifier"] != "verifier-1" || f.seen["client"] != "client-1" || f.seen["secret"] != "s3cret" {
		t.Errorf("the exchange did not send the verifier and client credentials: %v", f.seen)
	}
	if _, err := p.Exchange(context.Background(), "client-1", "s3cret", "https://app.example/cb", "bad", "v"); err == nil {
		t.Error("a refused exchange returned no error")
	}
	u := p.AuthURL("client-1", "https://app.example/cb", "st", "nn", "verifier-1", "ada@acme.example")
	for _, want := range []string{"code_challenge=" + Challenge("verifier-1"), "code_challenge_method=S256", "nonce=nn", "state=st", "scope=openid+email+profile"} {
		if !strings.Contains(u, want) {
			t.Errorf("auth URL missing %q: %s", want, u)
		}
	}
	if strings.Contains(u, "verifier-1") {
		t.Error("the PKCE verifier leaked into the authorization URL")
	}
}
