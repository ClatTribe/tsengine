package webagent

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestCrackHash covers the extracted-hash → plaintext gap: the agent dumps a hash (sqlmap) but had no
// way to recover the password to log in. crack_hash must recover a common/mangled password from its
// MD5/SHA1/SHA256 digest, auto-detect the type by length, honor an `extra` candidate, and report a
// preimage ONLY when it truly matches (§10 — never a guess).
func TestCrackHash(t *testing.T) {
	md5hex := func(s string) string { b := md5.Sum([]byte(s)); return hex.EncodeToString(b[:]) }
	sha1hex := func(s string) string { b := sha1.Sum([]byte(s)); return hex.EncodeToString(b[:]) }
	sha256hex := func(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
	cc := &Context{}

	// 1. plain common password (md5, auto-detected)
	if out := tCrackHash(cc, map[string]any{"hash": md5hex("password")}); !strings.Contains(out, `"password"`) {
		t.Errorf("md5(password) not cracked: %s", out)
	}
	// 2. mangled common password (base+suffix) via sha1
	if out := tCrackHash(cc, map[string]any{"hash": sha1hex("admin123"), "type": "sha1"}); !strings.Contains(out, `"admin123"`) {
		t.Errorf("sha1(admin123) not cracked: %s", out)
	}
	// 3. case + suffix mangle (Welcome2024) via sha256, auto-detected
	if out := tCrackHash(cc, map[string]any{"hash": sha256hex("Welcome2024")}); !strings.Contains(out, `"Welcome2024"`) {
		t.Errorf("sha256(Welcome2024) not cracked: %s", out)
	}
	// 4. an `extra` (target-specific) word is tried
	if out := tCrackHash(cc, map[string]any{"hash": md5hex("northwind!"), "extra": "northwind"}); !strings.Contains(out, `"northwind!"`) {
		t.Errorf("extra word not used: %s", out)
	}
	// 5. GROUNDING: a hash with no wordlist preimage is honestly "not cracked", never a false hit.
	if out := tCrackHash(cc, map[string]any{"hash": md5hex("Zx9!q_unlikely_7f3b__notinlist")}); strings.Contains(out, "CRACKED") {
		t.Errorf("false positive on an uncrackable hash: %s", out)
	}
	// 6. a non-hex / empty input errors rather than pretending
	if out := tCrackHash(cc, map[string]any{"hash": "not-a-hash"}); !strings.Contains(out, "ERROR") {
		t.Errorf("non-hex input should error: %s", out)
	}
}
