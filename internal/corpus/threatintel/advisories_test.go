package threatintel

import (
	"strings"
	"testing"
)

// THE THIRD TIME. vendorProject/product, then dueDate and ransomware use, now the reference
// URLs — all parsed and discarded from the same feed. Every one of the ~1,670 KEV entries
// carries them, and ThreatIntel.Advisories was never written by any source while the
// architecture doc listed "vendor advisory URLs" as shipped.
func TestParseKEV_ExtractsAdvisoryURLs(t *testing.T) {
	const body = `{"catalogVersion":"2026.08.21","dateReleased":"2026-08-21T12:00:00.0000Z",
	 "vulnerabilities":[
	  {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","dateAdded":"2021-12-10",
	   "notes":"https://logging.apache.org/log4j/2.x/security.html ; BOD 26-04: https://www.cisa.gov/directives/bod-26-04"}
	 ]}`
	kev, _, _, err := ParseKEV(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got := kev["CVE-2021-44228"].Advisories
	if len(got) != 2 {
		t.Fatalf("advisories = %v, want both URLs (the label prefix must not swallow the second)", got)
	}
	// Sorted: the corpus is diffed between refreshes, and unstable order would make every
	// rebuild look like a change to every entry.
	if got[0] > got[1] {
		t.Errorf("advisories are not sorted: %v", got)
	}
	for _, u := range got {
		if !strings.HasPrefix(u, "http") {
			t.Errorf("non-URL %q kept — a fragment of prose put in front of a responder does not resolve", u)
		}
	}
}

// Only real URLs. An entry whose note is prose has NO advisories, not a scrap of the prose:
// an empty list is honestly empty, a broken link is worse than nothing.
func TestParseKEV_ProseNotesYieldNoAdvisories(t *testing.T) {
	const body = `{"catalogVersion":"1","dateReleased":"2026-08-21T12:00:00.0000Z",
	 "vulnerabilities":[{"cveID":"CVE-2000-0001","dateAdded":"2020-01-01","notes":"Contact the vendor for guidance."}]}`
	kev, _, _, err := ParseKEV(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if got := kev["CVE-2000-0001"].Advisories; len(got) != 0 {
		t.Errorf("advisories = %v, want none", got)
	}
}

// The same URL listed twice is one advisory, and a trailing sentence period is not part of it.
func TestParseKEV_AdvisoriesAreDedupedAndTrimmed(t *testing.T) {
	const body = `{"catalogVersion":"1","dateReleased":"2026-08-21T12:00:00.0000Z",
	 "vulnerabilities":[{"cveID":"CVE-2000-0002","dateAdded":"2020-01-01",
	  "notes":"https://v.test/a ; https://v.test/a ; see https://v.test/b."}]}`
	kev, _, _, err := ParseKEV(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got := kev["CVE-2000-0002"].Advisories
	if len(got) != 2 {
		t.Fatalf("advisories = %v, want 2 distinct", got)
	}
	for _, u := range got {
		if strings.HasSuffix(u, ".") {
			t.Errorf("%q kept a trailing period — the link would not resolve", u)
		}
	}
}

// The whole point: the URLs must reach Entry.Advisories, which is the field the L1.5 hook
// already copies onto every CVE-bearing finding. Parsing them and leaving them in the KEV
// struct would repeat the bug in a new place.
func TestBuild_AdvisoriesReachTheCorpusEntry(t *testing.T) {
	const body = `{"catalogVersion":"1","dateReleased":"2026-08-21T12:00:00.0000Z",
	 "vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10",
	  "notes":"https://logging.apache.org/log4j/2.x/security.html"}]}`
	kev, asOf, ver, err := ParseKEV(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := Build(Sources{KEV: kev, KEVAsOf: asOf, KEVVer: ver, EPSSAsOf: asOf})
	e := entries["CVE-2021-44228"]
	if len(e.Advisories) != 1 {
		t.Fatalf("Entry.Advisories = %v — the field the hook reads is still empty", e.Advisories)
	}
	if e.KEV == nil || len(e.KEV.Advisories) != 1 {
		t.Error("the KEV status should keep them too — they are its own references")
	}
}
