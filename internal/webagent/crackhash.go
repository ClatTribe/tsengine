package webagent

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// crackhash.go closes a core post-exploitation gap: the agent regularly EXTRACTS password hashes (a
// dumped users table via dispatch_oss(sqlmap), a leaked config, a disclosed backup) but had no way to
// turn a hash back into the plaintext it needs to LOG IN and continue the chain (dump admin hash →
// crack → login → upload/flag). jwt_crack covers JWT HMAC secrets only; sqlmap's own dump-crack uses a
// tiny dict. This is an offline dictionary+mangling cracker for the unsalted fast hashes CTFs and
// legacy apps store (MD5/SHA1/SHA256). Grounded (§10): it reports a password ONLY when its hash
// actually equals the target (a real preimage, never a guess), and honestly says "not found" otherwise.
// Wordlist is GENERIC (top-common passwords + standard mangling rules), not tied to any target (§14.2).

// commonPasswords is a compact top-common list (rockyou-style). GENERIC — the universal weak passwords,
// no target-specific entries.
var commonPasswords = []string{
	"password", "123456", "123456789", "12345678", "12345", "1234567", "qwerty", "abc123", "admin",
	"letmein", "welcome", "monkey", "dragon", "master", "shadow", "superman", "michael", "football",
	"baseball", "trustno1", "iloveyou", "sunshine", "princess", "flower", "hottie", "loveme", "zaq1zaq1",
	"password1", "root", "toor", "test", "guest", "info", "adm", "user", "administrator", "changeme",
	"secret", "pass", "login", "access", "pass123", "test123", "admin123", "root123", "qwerty123",
	"password123", "welcome123", "p@ssw0rd", "passw0rd", "1q2w3e4r", "1qaz2wsx", "qazwsx", "654321",
	"batman", "starwars", "cheese", "computer", "hunter", "buster", "soccer", "harley", "ranger",
	"jordan", "tigger", "robert", "matthew", "jennifer", "michelle", "daniel", "andrew", "joshua",
	"summer", "winter", "autumn", "spring", "orange", "purple", "yellow", "silver", "golden",
	"ninja", "azerty", "solo", "loveyou", "whatever", "donald", "freedom", "hello", "hello123",
	"charlie", "aa123456", "qwertyuiop", "654321", "michael1", "superuser", "server", "database",
	"oracle", "mysql", "postgres", "redis", "docker", "kubernetes", "jenkins", "gitlab", "nginx",
	"apache", "tomcat", "manager", "webadmin", "sysadmin", "operator", "support", "service",
	"default", "temp", "demo", "sample", "example", "backup", "money", "bank", "finance", "payroll",
	"company", "business", "office", "work", "home", "family", "friend", "google", "facebook",
}

// mangleSuffixes are the standard rule-based suffixes appended to each base word.
var mangleSuffixes = []string{"", "1", "12", "123", "1234", "12345", "!", "@", "#", "$", "01", "007",
	"2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026", "123!", "1!", "@123"}

// maxCandidates bounds the search so a crack attempt stays snappy (a fraction of a second) and can't
// turn one tool call into a long compute — the ReAct-loop latency discipline (cf. discoverBudget).
const maxCandidates = 300000

// tCrackHash cracks an unsalted MD5/SHA1/SHA256 hash against the built-in wordlist + mangling rules.
// args: "hash" (required, hex), "type" (optional md5|sha1|sha256; auto-detected from length otherwise),
//
//	"extra" (optional comma-separated extra candidate words to try first, e.g. usernames/app name).
func tCrackHash(cc *Context, args map[string]any) string {
	h := strings.ToLower(strings.TrimSpace(argStr(args, "hash")))
	// tolerate a "algo:hash" or "hash" with surrounding punctuation
	if i := strings.LastIndex(h, ":"); i >= 0 && i < len(h)-1 {
		h = h[i+1:]
	}
	if h == "" || !isHex(h) {
		return "ERROR: hash is required (a hex md5/sha1/sha256 digest)"
	}
	typ := strings.ToLower(strings.TrimSpace(argStr(args, "type")))
	if typ == "" {
		switch len(h) {
		case 32:
			typ = "md5"
		case 40:
			typ = "sha1"
		case 64:
			typ = "sha256"
		default:
			return fmt.Sprintf("ERROR: can't auto-detect hash type from length %d — pass type=md5|sha1|sha256", len(h))
		}
	}
	digest, ok := digestFn(typ)
	if !ok {
		return "ERROR: unsupported type " + typ + " (md5|sha1|sha256)"
	}

	// extra candidates (agent-supplied context: the username, app name, etc.) tried first + mangled.
	var bases []string
	for _, e := range strings.Split(argStr(args, "extra"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			bases = append(bases, e)
		}
	}
	bases = append(bases, commonPasswords...)

	tried := 0
	for _, base := range bases {
		for _, v := range caseVariants(base) {
			for _, suf := range mangleSuffixes {
				cand := v + suf
				if tried++; tried > maxCandidates {
					return fmt.Sprintf("not cracked — %s not in the built-in wordlist (tried %d candidates). Try dispatch_oss(hydra) for an online brute, or a bigger wordlist.", typ, tried-1)
				}
				if digest(cand) == h {
					return fmt.Sprintf("CRACKED (%s): %q  — log in with this password via send_request.", typ, cand)
				}
			}
		}
	}
	return fmt.Sprintf("not cracked — %s hash not in the built-in wordlist (tried %d). Try dispatch_oss(hydra) or supply extra=<candidate words>.", typ, tried)
}

func caseVariants(w string) []string {
	out := []string{w}
	if t := strings.Title(w); t != w { //nolint:staticcheck // ASCII passwords; Title is fine here
		out = append(out, t)
	}
	if u := strings.ToUpper(w); u != w && u != strings.Title(w) {
		out = append(out, u)
	}
	return out
}

func digestFn(typ string) (func(string) string, bool) {
	switch typ {
	case "md5":
		return func(s string) string { b := md5.Sum([]byte(s)); return hex.EncodeToString(b[:]) }, true
	case "sha1":
		return func(s string) string { b := sha1.Sum([]byte(s)); return hex.EncodeToString(b[:]) }, true
	case "sha256":
		return func(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }, true
	}
	return nil, false
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
