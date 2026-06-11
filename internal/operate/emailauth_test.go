package operate

import (
	"context"
	"errors"
	"testing"
)

// fakeResolver answers from a fixed map; absent names return an NXDOMAIN-like error.
type fakeResolver map[string][]string

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if recs, ok := f[name]; ok {
		return recs, nil
	}
	return nil, errors.New("no such host")
}

func TestFetchDomain_EnforcedIsClean(t *testing.T) {
	r := fakeResolver{
		"_dmarc.acme.com":            {"v=DMARC1; p=reject; rua=mailto:dmarc@acme.com"},
		"acme.com":                   {"v=spf1 include:_spf.google.com ~all"},
		"google._domainkey.acme.com": {"v=DKIM1; k=rsa; p=MIGfMA0..."},
	}
	e := &EmailAuth{Resolver: r}
	dc := e.FetchDomain(context.Background(), "acme.com")
	if dc.DMARC != "reject" || !dc.SPF || !dc.DKIM {
		t.Fatalf("a hardened domain should resolve reject/SPF/DKIM, got %+v", dc)
	}
	// And it should yield ZERO email-auth findings (the hardened-input invariant).
	if fs := Assess(Workspace{Domains: []DomainConfig{dc}}, Options{}); len(fs) != 0 {
		t.Fatalf("hardened domain should produce no findings, got %d", len(fs))
	}
}

func TestFetchDomain_AbsentRecordsAreGaps(t *testing.T) {
	e := &EmailAuth{Resolver: fakeResolver{}} // every lookup misses
	dc := e.FetchDomain(context.Background(), "spoofable.com")
	if dc.DMARC != "" || dc.SPF || dc.DKIM {
		t.Fatalf("a domain with no records should be all-absent, got %+v", dc)
	}
	// The negative lookup is grounded evidence: the email-auth checks fire.
	fs := Assess(Workspace{Domains: []DomainConfig{dc}}, Options{})
	if len(fs) == 0 {
		t.Fatal("a domain with no DMARC/SPF/DKIM should produce findings")
	}
}

func TestParseDMARC(t *testing.T) {
	cases := map[string]string{
		"v=DMARC1; p=reject":              "reject",
		"v=DMARC1;p=quarantine; pct=100":  "quarantine",
		"v=DMARC1; p=none":                "none",
		"v=spf1 -all":                     "", // not a DMARC record
		"v=DMARC1; rua=mailto:x@acme.com": "", // no p= tag
	}
	for rec, want := range cases {
		if got := parseDMARC([]string{rec}); got != want {
			t.Errorf("parseDMARC(%q) = %q, want %q", rec, got, want)
		}
	}
}

func TestFetchDomain_WeakDMARCFlagged(t *testing.T) {
	r := fakeResolver{
		"_dmarc.weak.com": {"v=DMARC1; p=none"}, // monitoring only — not enforcing
		"weak.com":        {"v=spf1 ~all"},
	}
	dc := (&EmailAuth{Resolver: r}).FetchDomain(context.Background(), "weak.com")
	if dc.DMARC != "none" {
		t.Fatalf("p=none should parse as none, got %q", dc.DMARC)
	}
	fs := Assess(Workspace{Domains: []DomainConfig{dc}}, Options{})
	var sawDMARC bool
	for _, f := range fs {
		if f.RuleID == "operate::dmarc-not-enforced" {
			sawDMARC = true
		}
	}
	if !sawDMARC {
		t.Fatal("p=none (not quarantine/reject) should flag dmarc-not-enforced")
	}
}

func TestDomainsFromUsers(t *testing.T) {
	users := []User{
		{Email: "alice@acme.com"},
		{Email: "bob@acme.com"},   // dup domain
		{Email: "carol@Acme.com"}, // case-fold dup
		{Email: "dave@sub.acme.io"},
		{Email: "broken"}, // no @ → skipped
	}
	got := DomainsFromUsers(users)
	want := []string{"acme.com", "sub.acme.io"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("DomainsFromUsers = %v, want %v", got, want)
	}
}

func TestFetchDomains_Dedupes(t *testing.T) {
	e := &EmailAuth{Resolver: fakeResolver{}}
	got := e.FetchDomains(context.Background(), []string{"acme.com", "ACME.com", "acme.com"})
	if len(got) != 1 {
		t.Fatalf("FetchDomains should dedupe case-insensitively, got %d", len(got))
	}
}
