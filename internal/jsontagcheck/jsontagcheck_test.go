// Package jsontagcheck holds no runtime code. It gates one thing the compiler cannot see:
// `omitempty` on a bare time.Time is a NO-OP, and the field it is written on will ship the zero
// time to every consumer.
//
// This is not a style rule. It shipped two false claims on the incident queue at once:
//
//   - every open incident rendered "acknowledged", because `!!i.acknowledged_at` is true for the
//     non-empty string "0001-01-01T00:00:00Z". The badge REPLACES the Acknowledge button, so the
//     one action in the alert-response path could not be taken — on a page whose own SOC scorecard
//     simultaneously read "0 acknowledged";
//   - every incident claimed a CISA federal remediation deadline had PASSED, because the zero time
//     parses to year 1, which is in the past — on incidents with no CVE behind them at all.
//
// In both cases the consumer was reading the contract the tag advertises. The tag was the lie.
// Go 1.24's `omitzero` is the fix and does exactly what `omitempty` was assumed to do here.
package jsontagcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Bare `time.Time` only. `*time.Time` and `map[...]time.Time` are NOT the bug — omitempty
// correctly omits a nil pointer and an empty map — so flagging them would be noise, and noise in
// a guard is how a guard stops being read.
var badTag = regexp.MustCompile(`(?:^|[^*\]])\btime\.Time\s+` + "`" + `json:"[^"]+,omitempty"` + "`")

func TestNoTimeTimeCarriesOmitempty(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable dir is not this test's business
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".next", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(b), "\n") {
			if badTag.MatchString(line) {
				bad = append(bad, filepath.ToSlash(rel)+":"+itoa(i+1)+"  "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Errorf("`omitempty` on a bare time.Time does nothing — the option has no effect on a "+
			"struct, so each of these ships \"0001-01-01T00:00:00Z\" for an event that never "+
			"happened:\n\n  %s\n\nUse `omitzero` (Go 1.24+), which omits the zero time and keeps a "+
			"real one. A consumer that reads the field's PRESENCE as \"it happened\" is not making "+
			"a mistake — it is reading the contract this tag advertises.",
			strings.Join(bad, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
