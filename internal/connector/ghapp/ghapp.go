// Package ghapp authenticates as a GitHub App: it mints the App JWT and exchanges it for a
// per-installation access token. This is the credential the PR-review bot POSTS with.
//
// WHY A SECOND GITHUB CREDENTIAL. The onboarded GitHub connection is an OAuth token with
// `repo read:org` — it can read code and open a pull request AS THE USER who connected. A check-run
// cannot be created by a user token at all (GitHub only lets an App own check-runs), and a review
// comment posted by a user token appears as that person, not as the bot. So the two live writes
// the review bot exists for — the merge-gating check-run and the inline comments — need an App
// identity, which this package provides. Read-side work keeps using the OAuth connection.
//
// What this package refuses: it never persists an installation token (they live 1h; the cache is
// in memory and re-minted on expiry) and never falls back to the OAuth token, because a review
// posted as a person when the customer expected the bot is a claim about who reviewed the code.
package ghapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenSource is what the poster needs: a token for one installation. The App satisfies it; tests
// inject a fake.
type TokenSource interface {
	InstallationToken(ctx context.Context, installationID string) (string, error)
}

// App is a configured GitHub App.
type App struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	APIBase    string       // default https://api.github.com
	HTTP       *http.Client // default http.DefaultClient
	Now        func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	token   string
	expires time.Time
}

// ParsePrivateKey reads the PEM GitHub hands out when a key is generated (PKCS#1 "RSA PRIVATE KEY";
// PKCS#8 is accepted too).
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ghapp: private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ghapp: private key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("ghapp: private key is not RSA")
	}
	return rk, nil
}

// FromEnv builds the App from GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY (PEM inline, \n-escaped
// accepted) or GITHUB_APP_PRIVATE_KEY_FILE. Returns nil when unset — the honest "no App on this
// deployment" — and an error when set but unusable, because a deployment that THINKS it has an App
// and silently has none would report every review as not posted for the wrong reason.
func FromEnv() (*App, error) {
	id := strings.TrimSpace(os.Getenv("GITHUB_APP_ID"))
	key := os.Getenv("GITHUB_APP_PRIVATE_KEY")
	if f := os.Getenv("GITHUB_APP_PRIVATE_KEY_FILE"); key == "" && f != "" {
		b, err := os.ReadFile(f) //nolint:gosec // operator-configured path
		if err != nil {
			return nil, fmt.Errorf("ghapp: GITHUB_APP_PRIVATE_KEY_FILE: %w", err)
		}
		key = string(b)
	}
	if id == "" && key == "" {
		return nil, nil
	}
	if id == "" || key == "" {
		return nil, errors.New("ghapp: GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY(_FILE) must both be set")
	}
	pk, err := ParsePrivateKey([]byte(strings.ReplaceAll(key, `\n`, "\n")))
	if err != nil {
		return nil, err
	}
	return &App{ID: id, PrivateKey: pk}, nil
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *App) base() string {
	if a.APIBase == "" {
		return "https://api.github.com"
	}
	return strings.TrimRight(a.APIBase, "/")
}

func (a *App) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return http.DefaultClient
}

// JWT mints the App's bearer: RS256 over {iat: now-60s, exp: now+9m, iss: app id}. GitHub caps exp at
// 10 minutes and rejects an iat in the future, hence the skew allowance on both ends. Hand-rolled
// because it is three base64 segments and one signature; a JWT library would be a dependency for
// exactly this.
func (a *App) JWT() (string, error) {
	if a.PrivateKey == nil || a.ID == "" {
		return "", errors.New("ghapp: app id and private key required")
	}
	now := a.now()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-60 * time.Second).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": a.ID})
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.PrivateKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("ghapp: sign jwt: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// InstallationToken exchanges the App JWT for the installation's access token
// (POST /app/installations/{id}/access_tokens), cached until a minute before it expires.
func (a *App) InstallationToken(ctx context.Context, installationID string) (string, error) {
	installationID = strings.TrimSpace(installationID)
	if installationID == "" {
		return "", errors.New("ghapp: installation id required")
	}
	a.mu.Lock()
	if c, ok := a.cache[installationID]; ok && a.now().Before(c.expires.Add(-time.Minute)) {
		a.mu.Unlock()
		return c.token, nil
	}
	a.mu.Unlock()

	jwt, err := a.JWT()
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base()+"/app/installations/"+installationID+"/access_tokens", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := a.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("ghapp: installation token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return "", fmt.Errorf("ghapp: HTTP 401 — the App id or private key is wrong: %s", msg)
		case http.StatusNotFound:
			return "", fmt.Errorf("ghapp: HTTP 404 — installation %s does not belong to this App (was it uninstalled, or is the id from a different App?): %s", installationID, msg)
		}
		return "", fmt.Errorf("ghapp: HTTP %d: %s", resp.StatusCode, msg)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		return "", errors.New("ghapp: installation token response carried no token")
	}
	a.mu.Lock()
	if a.cache == nil {
		a.cache = map[string]cached{}
	}
	a.cache[installationID] = cached{token: out.Token, expires: out.ExpiresAt}
	a.mu.Unlock()
	return out.Token, nil
}
