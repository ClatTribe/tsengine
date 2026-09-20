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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// The JWT is what GitHub specifies: RS256, iss = app id, iat slightly in the past, exp under ten
// minutes — verified with the public key rather than trusted by shape.
func TestJWT_IsRS256OverTheAppClaims(t *testing.T) {
	k, pemBytes := testKey(t)
	pk, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	a := &App{ID: "12345", PrivateKey: pk, Now: func() time.Time { return now }}
	tok, err := a.JWT()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt must have three segments: %q", tok)
	}
	var claims map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &claims)
	if claims["iss"] != "12345" || int64(claims["iat"].(float64)) != now.Add(-60*time.Second).Unix() || int64(claims["exp"].(float64)) != now.Add(9*time.Minute).Unix() {
		t.Errorf("claims: %v", claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Errorf("signature does not verify with the App's public key: %v", err)
	}
}

// The installation token is exchanged with the JWT as bearer, cached until near expiry, and a 404
// is explained (the id belongs to another App or the App was uninstalled) rather than left bare.
func TestInstallationToken_ExchangesCachesAndExplainsFailure(t *testing.T) {
	_, pemBytes := testKey(t)
	pk, _ := ParsePrivateKey(pemBytes)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ey") || r.Method != http.MethodPost {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/app/installations/777/access_tokens":
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_live", "expires_at": time.Now().Add(time.Hour)})
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		}
	}))
	defer srv.Close()
	a := &App{ID: "1", PrivateKey: pk, APIBase: srv.URL}
	tok, err := a.InstallationToken(context.Background(), "777")
	if err != nil || tok != "ghs_live" {
		t.Fatalf("token: %q %v", tok, err)
	}
	if _, err := a.InstallationToken(context.Background(), "777"); err != nil || calls != 1 {
		t.Errorf("second call must be served from cache: calls=%d err=%v", calls, err)
	}
	if _, err := a.InstallationToken(context.Background(), "999"); err == nil || !strings.Contains(err.Error(), "does not belong to this App") {
		t.Errorf("a 404 must be explained: %v", err)
	}
	if _, err := a.InstallationToken(context.Background(), ""); err == nil {
		t.Error("an empty installation id must be refused, not sent")
	}
}

// FromEnv: unset is nil (no App, honestly), half-set is an error, \n-escaped PEM is accepted.
func TestFromEnv(t *testing.T) {
	t.Setenv("GITHUB_APP_ID", "")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "")
	t.Setenv("GITHUB_APP_PRIVATE_KEY_FILE", "")
	if a, err := FromEnv(); a != nil || err != nil {
		t.Errorf("unset must be nil,nil: %v %v", a, err)
	}
	t.Setenv("GITHUB_APP_ID", "42")
	if _, err := FromEnv(); err == nil {
		t.Error("id without key must error, never a half-configured App")
	}
	_, pemBytes := testKey(t)
	t.Setenv("GITHUB_APP_PRIVATE_KEY", strings.ReplaceAll(string(pemBytes), "\n", `\n`))
	a, err := FromEnv()
	if err != nil || a == nil || a.ID != "42" {
		t.Errorf("escaped PEM must parse: %v %v", a, err)
	}
}
