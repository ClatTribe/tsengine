package operate

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// reservedChecks are declared gaps that no fetcher can currently produce, with the reason. Being on
// this list is a claim that must stay true, so the guard below checks it in BOTH directions.
var reservedChecks = map[string]string{
	"users": "all three fetchers fail LOUDLY on a user-list error — Okta's pagination and the " +
		"Graph/Directory page calls each return an error from Fetch, so there is no partial read " +
		"that could leave the directory half-known. Reserved for a future partial path (or a " +
		"caller that declares it) rather than removed, because the renderer already handles it.",
}

// Every declared gap must be reachable, or declared unreachable on purpose.
//
// THIS IS THE BUG THAT MADE THE GUARD. unavailableChecks declared "mfa" — with a title, a
// what-it-would-have-found and a remedy, all written — and nothing ever appended it. The entry read
// as coverage; the code had none. Meanwhile Okta's per-user factor read failed into MFA's zero
// value, which is the value that fires "Administrator without MFA" at CRITICAL, so the missing
// disclosure was not cosmetic: it was the thing standing between a failed API call and a fabricated
// critical finding against a correctly-configured admin.
//
// A declared-and-never-emitted signal is exactly what platformapi.AllDegradationKinds guards against
// for degradations. This is the same guarantee for identity coverage.
func TestEveryDeclaredGapIsEmittedSomewhere(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			t.Fatal(rerr)
		}
		src.Write(b)
	}
	body := src.String()

	for key := range unavailableChecks {
		// Appended anywhere as a literal: `ws.Unavailable = append(ws.Unavailable, "mfa")`.
		emitted := regexp.MustCompile(`Unavailable,\s*"` + regexp.QuoteMeta(key) + `"`).MatchString(body)
		reason, reserved := reservedChecks[key]
		switch {
		case emitted && reserved:
			t.Errorf("gap %q is listed as reserved (%q) but IS emitted — a stale exemption hides the "+
				"next unwired gap behind a name that looks accounted for", key, reason)
		case !emitted && !reserved:
			t.Errorf("gap %q is declared in unavailableChecks and never appended to Workspace."+
				"Unavailable.\n\nIt reads as coverage the code does not have. That is not cosmetic: "+
				"%q was in exactly this state while Okta's failed per-user factor read left MFA at "+
				"false — the value that fires a CRITICAL finding — so the missing disclosure was all "+
				"that stood between an API error and a fabricated critical against a correct admin.\n\n"+
				"Wire it in a fetcher, or add it to reservedChecks with the reason it cannot occur.",
				key, key)
		}
	}
	for key := range reservedChecks {
		if _, ok := unavailableChecks[key]; !ok {
			t.Errorf("reservedChecks names %q, which unavailableChecks does not declare — a stale "+
				"exemption silently covers a future gap that reuses the name", key)
		}
	}
}
