package platformapi

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/operate"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"acme.com":              "acme.com",
		"  ACME.com ":           "acme.com",
		"https://acme.com/path": "acme.com",
		"http://sub.acme.co.uk": "sub.acme.co.uk",
		"acme.com.":             "acme.com",
		"acme.com:443":          "acme.com",
		// invalid → ""
		"localhost":    "",
		"127.0.0.1":    "",
		"not a domain": "",
		"":             "",
		"acme":         "",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAssessEmailAuth_Scoring(t *testing.T) {
	// A hardened domain (DMARC reject + SPF + DKIM) → no findings → A / 100.
	hard := assessEmailAuth(operate.DomainConfig{Name: "acme.com", DMARC: "reject", SPF: true, DKIM: true})
	if hard.Score != 100 || hard.Grade != "A" {
		t.Errorf("hardened domain should score 100/A, got %d/%s", hard.Score, hard.Grade)
	}
	if len(hard.Findings) != 0 {
		t.Errorf("hardened domain should have no findings, got %+v", hard.Findings)
	}
	for _, c := range hard.Checks {
		if !c.OK {
			t.Errorf("hardened domain check %q should pass", c.Name)
		}
	}

	// A wide-open domain (no DMARC/SPF/DKIM) → penalised → lower grade + findings.
	open := assessEmailAuth(operate.DomainConfig{Name: "weak.com"})
	if open.Score >= hard.Score {
		t.Errorf("open domain (%d) must score worse than hardened (%d)", open.Score, hard.Score)
	}
	if len(open.Findings) == 0 {
		t.Error("open domain should surface grounded email-auth findings")
	}
	if open.Grade == "A" {
		t.Errorf("a domain with no DMARC must not get an A, got %s (score %d)", open.Grade, open.Score)
	}
}

func TestAssessLimiter(t *testing.T) {
	l := &assessLimiter{hit: map[string][]time.Time{}, max: 3}
	now := time.Unix(1700000000, 0)
	for i := 0; i < 3; i++ {
		if !l.allow("1.2.3.4", now) {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if l.allow("1.2.3.4", now) {
		t.Error("the 4th request in the window must be rate-limited")
	}
	if !l.allow("5.6.7.8", now) {
		t.Error("a different IP must not be limited")
	}
	// after the window rolls, the IP is allowed again
	if !l.allow("1.2.3.4", now.Add(61*time.Second)) {
		t.Error("after the minute window, the IP should be allowed again")
	}
}

func TestAssessEmailAuth_DKIMMessageIsHonest(t *testing.T) {
	// DKIM selectors can't be enumerated, so a "not found" result must NOT falsely assert the
	// domain's mail is unsigned (grounding §10) — it states the best-effort limitation instead.
	res := assessEmailAuth(operate.DomainConfig{Name: "x.com", DMARC: "reject", SPF: true, DKIM: false})
	var dkim string
	for _, c := range res.Checks {
		if c.Name == "DKIM" {
			dkim = c.Detail
		}
	}
	if strings.Contains(dkim, "aren't cryptographically signed") {
		t.Errorf("DKIM-absent detail must not falsely assert mail is unsigned: %q", dkim)
	}
	if !strings.Contains(dkim, "selector") {
		t.Errorf("DKIM-absent detail should explain the selector limitation: %q", dkim)
	}
}
