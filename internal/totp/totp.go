// Package totp implements time-based one-time passwords (RFC 6238, HOTP per RFC 4226) for the
// second sign-in factor, plus single-use recovery codes.
//
// It is deliberately small and dependency-free. What it decides, and what it leaves to the caller:
//
//   - Verify accepts the current 30-second step and ONE step either side (clock drift between a phone
//     and the server is normal), and returns WHICH step matched. The caller stores it and refuses any
//     step at or below the last one accepted — a code observed over a shoulder or in a proxy log must
//     not work a second time inside its window. Replay protection needs state, so it lives with the
//     user record, not here.
//   - Codes are compared in constant time.
//   - Recovery codes are returned once in plain text and stored only as SHA-256 hashes; a used code is
//     removed, so each works exactly once.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238's default and what every authenticator app implements
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Period is the step length every authenticator app uses.
	Period = 30
	// Digits is the code length every authenticator app shows.
	Digits = 6
	// Skew is how many steps either side of now are accepted.
	Skew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a fresh 160-bit secret, base32-encoded without padding (the form authenticator
// apps accept for manual entry).
func NewSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// URI is the otpauth:// URI an authenticator app imports (as a QR code or a pasted link).
func URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(Period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// decode accepts the secret as users and apps write it: any case, spaces allowed.
func decode(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, errors.New("totp: empty secret")
	}
	return b32.DecodeString(s)
}

// hotp is RFC 4226 §5.3 dynamic truncation.
func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// Step is the time step a moment falls in.
func Step(t time.Time) int64 { return t.Unix() / Period }

// Code returns the code for a moment (used by tests and by nothing in the request path).
func Code(secret string, t time.Time) (string, error) {
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	step := Step(t)
	if step < 0 {
		return "", errors.New("totp: time before the Unix epoch")
	}
	return hotp(key, uint64(step), Digits), nil
}

// Verify reports whether code is valid at now within ±Skew steps, and which step it matched. The
// caller MUST refuse a matched step <= the last one it accepted (see the package doc).
func Verify(secret, code string, now time.Time) (step int64, ok bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits {
		return 0, false
	}
	key, err := decode(secret)
	if err != nil {
		return 0, false
	}
	cur := Step(now)
	matched, found := int64(0), false
	// Check every candidate rather than returning on the first match, so the time taken does not
	// reveal which step (if any) matched.
	for d := int64(-Skew); d <= Skew; d++ {
		s := cur + d
		if s < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(s), Digits)), []byte(code)) == 1 && !found {
			matched, found = s, true
		}
	}
	return matched, found
}

// RecoveryCount is how many recovery codes a user is given.
const RecoveryCount = 10

// NewRecoveryCodes returns RecoveryCount codes in display form (xxxxx-xxxxx) and their hashes for
// storage. The plain codes are shown once and never stored.
func NewRecoveryCodes() (plain, hashes []string, err error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for i := 0; i < RecoveryCount; i++ {
		b := make([]byte, 7)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		s := strings.ToLower(enc.EncodeToString(b))[:10]
		code := s[:5] + "-" + s[5:]
		plain = append(plain, code)
		hashes = append(hashes, HashRecovery(code))
	}
	return plain, hashes, nil
}

// HashRecovery normalises a recovery code as people type it (case, spaces, the dash) and hashes it.
func HashRecovery(code string) string {
	c := strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:])
}

// ConsumeRecovery returns the remaining hashes with code's removed, and whether it was present. The
// comparison runs over every stored hash so its timing does not depend on where the match is.
func ConsumeRecovery(hashes []string, code string) (remaining []string, ok bool) {
	h := []byte(HashRecovery(code))
	idx := -1
	for i, s := range hashes {
		if subtle.ConstantTimeCompare([]byte(s), h) == 1 && idx < 0 {
			idx = i
		}
	}
	if idx < 0 {
		return hashes, false
	}
	remaining = make([]string, 0, len(hashes)-1)
	remaining = append(remaining, hashes[:idx]...)
	remaining = append(remaining, hashes[idx+1:]...)
	return remaining, true
}
