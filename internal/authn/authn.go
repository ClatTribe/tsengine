// Package authn handles password hashing and session-token generation for the platform's
// real user accounts. Password storage uses PBKDF2-HMAC-SHA256 (stdlib crypto/pbkdf2,
// Go 1.24+) with a per-password random salt and an OWASP-grade iteration count — no
// third-party dependency. Hashes are self-describing so the cost can be raised later
// without breaking existing users.
package authn

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	iterations = 600_000 // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
	keyLen     = 32
	saltLen    = 16
)

// ErrWeakPassword is returned when a password is too short to hash.
var ErrWeakPassword = errors.New("authn: password must be at least 8 characters")

// HashPassword returns a self-describing PBKDF2 hash: "pbkdf2$sha256$<iter>$<salt>$<dk>".
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", ErrWeakPassword
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2$sha256$%d$%s$%s", iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifyPassword reports whether password matches the encoded hash, in constant time.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[2])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[3])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[4])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewToken returns a 256-bit URL-safe random token (for session ids).
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
