// Package oidc is the relying-party half of OpenID Connect sign-in: discover a provider, build the
// authorization request (with PKCE and a nonce), exchange the code, and VERIFY the ID token.
//
// It is dependency-free on purpose, and the verification is where the care goes, because an SSO
// login that accepts a forged or misdirected token is a front door with no lock:
//
//   - The algorithm comes from a fixed allowlist (RS256, ES256). "none" and every HMAC algorithm are
//     refused — HS256 with the provider's PUBLIC key as the secret is the classic forgery.
//   - The signing key is the provider's own, fetched from its jwks_uri and selected by kid; an unknown
//     kid triggers ONE refetch (providers rotate keys) and is then refused.
//   - iss must equal the configured issuer exactly, aud must contain our client id (and azp must be us
//     when aud names several parties), exp/nbf are checked with a small skew, and the nonce must be
//     the one this login created — a token minted for another login cannot be replayed into this one.
//   - The discovery document's own issuer must equal the configured one, so a provider cannot be
//     pointed at another's metadata.
//
// What it deliberately does not do: decide WHO may sign in. That is the caller's job, against its own
// records (internal/platformapi/sso.go).
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Provider is a discovered OpenID provider.
type Provider struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	client *http.Client
	mu     sync.Mutex
	keys   map[string]crypto.PublicKey
}

// skew tolerates clock differences between us and the provider.
const skew = 2 * time.Minute

func normIssuer(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }

// Discover fetches the provider's metadata. The issuer must be https, and the document's own issuer
// must equal it.
func Discover(ctx context.Context, client *http.Client, issuer string) (*Provider, error) {
	issuer = normIssuer(issuer)
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("oidc: the issuer must be an https URL")
	}
	var p Provider
	if err := getJSON(ctx, client, issuer+"/.well-known/openid-configuration", &p); err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	if normIssuer(p.Issuer) != issuer {
		return nil, fmt.Errorf("oidc: the provider's metadata names issuer %q, not %q", p.Issuer, issuer)
	}
	for name, v := range map[string]string{"authorization_endpoint": p.AuthorizationEndpoint, "token_endpoint": p.TokenEndpoint, "jwks_uri": p.JWKSURI} {
		if pu, err := url.Parse(v); err != nil || pu.Scheme != "https" {
			return nil, fmt.Errorf("oidc: the provider's %s is not an https URL", name)
		}
	}
	p.client = client
	return &p, nil
}

func getJSON(ctx context.Context, client *http.Client, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
}

// Random returns a URL-safe random string (state ids, nonces, PKCE verifiers).
func Random() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Challenge is the S256 PKCE challenge for a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthURL builds the authorization request.
func (p *Provider) AuthURL(clientID, redirectURI, state, nonce, verifier, loginHint string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", Challenge(verifier))
	q.Set("code_challenge_method", "S256")
	if loginHint != "" {
		q.Set("login_hint", loginHint)
	}
	sep := "?"
	if strings.Contains(p.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return p.AuthorizationEndpoint + sep + q.Encode()
}

// Exchange trades an authorization code for the raw ID token.
func (p *Provider) Exchange(ctx context.Context, clientID, clientSecret, redirectURI, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc: token exchange: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc: token exchange refused (HTTP %d): %s %s", resp.StatusCode, out.Error, out.Desc)
	}
	if out.IDToken == "" {
		return "", errors.New("oidc: the provider returned no id_token")
	}
	return out.IDToken, nil
}

// Claims are the ID-token claims the caller decides on.
type Claims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"-"`
	Name          string   `json:"name"`
	AMR           []string `json:"amr"`
}

// MFA reports whether the provider says a second factor was used (RFC 8176 amr values).
func (c Claims) MFA() bool {
	for _, m := range c.AMR {
		switch strings.ToLower(m) {
		case "mfa", "otp", "hwk", "swk", "sms", "fido", "face", "fpt", "iris", "retina", "vbm", "pop":
			return true
		}
	}
	return false
}

// ErrInvalidToken wraps every reason a token is refused.
var ErrInvalidToken = errors.New("oidc: invalid ID token")

// Verify checks an ID token's signature and claims against this provider, our client id, and the
// nonce this login created.
func (p *Provider) Verify(ctx context.Context, raw, clientID, nonce string, now time.Time) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: not a JWS", ErrInvalidToken)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSeg(parts[0], &hdr); err != nil {
		return Claims{}, fmt.Errorf("%w: header: %v", ErrInvalidToken, err)
	}
	if hdr.Alg != "RS256" && hdr.Alg != "ES256" {
		return Claims{}, fmt.Errorf("%w: algorithm %q is not accepted", ErrInvalidToken, hdr.Alg)
	}
	key, err := p.key(ctx, hdr.Kid)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature encoding", ErrInvalidToken)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if hdr.Alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return Claims{}, fmt.Errorf("%w: signature does not verify", ErrInvalidToken)
		}
	case *ecdsa.PublicKey:
		if hdr.Alg != "ES256" || len(sig) != 64 {
			return Claims{}, fmt.Errorf("%w: signature does not verify", ErrInvalidToken)
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(k, digest[:], r, s) {
			return Claims{}, fmt.Errorf("%w: signature does not verify", ErrInvalidToken)
		}
	default:
		return Claims{}, fmt.Errorf("%w: unsupported key", ErrInvalidToken)
	}

	var c struct {
		Iss           string          `json:"iss"`
		Aud           json.RawMessage `json:"aud"`
		Azp           string          `json:"azp"`
		Exp           float64         `json:"exp"`
		Nbf           float64         `json:"nbf"`
		Nonce         string          `json:"nonce"`
		Sub           string          `json:"sub"`
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
		Name          string          `json:"name"`
		AMR           []string        `json:"amr"`
	}
	if err := decodeSeg(parts[1], &c); err != nil {
		return Claims{}, fmt.Errorf("%w: claims: %v", ErrInvalidToken, err)
	}
	if normIssuer(c.Iss) != normIssuer(p.Issuer) {
		return Claims{}, fmt.Errorf("%w: issued by %q, not the configured provider", ErrInvalidToken, c.Iss)
	}
	aud := audiences(c.Aud)
	if !contains(aud, clientID) {
		return Claims{}, fmt.Errorf("%w: not issued for this application", ErrInvalidToken)
	}
	if len(aud) > 1 && c.Azp != clientID {
		return Claims{}, fmt.Errorf("%w: issued to several parties and not authorized for this one", ErrInvalidToken)
	}
	if c.Exp == 0 || now.After(time.Unix(int64(c.Exp), 0).Add(skew)) {
		return Claims{}, fmt.Errorf("%w: expired", ErrInvalidToken)
	}
	if c.Nbf != 0 && now.Add(skew).Before(time.Unix(int64(c.Nbf), 0)) {
		return Claims{}, fmt.Errorf("%w: not valid yet", ErrInvalidToken)
	}
	if nonce == "" || c.Nonce != nonce {
		return Claims{}, fmt.Errorf("%w: the nonce does not match this sign-in", ErrInvalidToken)
	}
	if c.Sub == "" {
		return Claims{}, fmt.Errorf("%w: no subject", ErrInvalidToken)
	}
	out := Claims{Subject: c.Sub, Email: strings.ToLower(strings.TrimSpace(c.Email)), Name: c.Name, AMR: c.AMR}
	// email_verified arrives as a boolean or (Entra, some Okta setups) a string; anything else is false.
	switch strings.Trim(string(c.EmailVerified), `" `) {
	case "true":
		out.EmailVerified = true
	}
	return out, nil
}

func audiences(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v && v != "" {
			return true
		}
	}
	return false
}

func decodeSeg(seg string, into any) error {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// key returns the signing key for kid, refetching the JWKS once when it is unknown (key rotation).
func (p *Provider) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.keys[kid]; ok {
		return k, nil
	}
	keys, err := fetchJWKS(ctx, p.client, p.JWKSURI)
	if err != nil {
		return nil, err
	}
	p.keys = keys
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	// A provider with exactly one key may omit kid from the header.
	if kid == "" && len(keys) == 1 {
		for _, k := range keys {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no signing key %q at the provider", kid)
}

func fetchJWKS(ctx context.Context, client *http.Client, u string) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := getJSON(ctx, client, u, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	out := map[string]crypto.PublicKey{}
	b64 := base64.RawURLEncoding
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := b64.DecodeString(k.N)
			e, err2 := b64.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(n) < 256 { // refuse RSA keys under 2048 bits
				continue
			}
			out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := b64.DecodeString(k.X)
			y, err2 := b64.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
				continue
			}
			out[k.Kid] = pub
		}
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: the provider published no usable signing key")
	}
	return out, nil
}
