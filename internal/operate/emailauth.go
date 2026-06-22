package operate

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Resolver is the DNS surface the email-auth fetcher needs — satisfied by *net.Resolver.
// Injectable so the lookups are deterministic in tests (no real DNS).
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// defaultDKIMSelectors are the selectors the big providers publish under. DKIM keys live
// at <selector>._domainkey.<domain> and DNS can't enumerate selectors, so we probe the
// well-known ones: google (Google Workspace), selector1/selector2 (Microsoft 365),
// k1/k2/k3 (Mailchimp/Mandrill, SendGrid via "s1"/"s2"), plus the generic defaults.
var defaultDKIMSelectors = []string{
	"google", "selector1", "selector2", "default", "dkim", "mail", "k1", "k2", "k3", "s1", "s2",
}

// EmailAuth resolves a domain's live email-auth posture (DMARC / SPF / DKIM) from public
// DNS — the live counterpart to a snapshot's DomainConfig. It is grounded: every field
// reflects a real TXT record (or its documented absence). Email spoofing is the #1 SMB
// attack vector and DMARC enforcement is a concrete compliance control, so making this
// live (vs snapshot-only) closes a real detection gap for the non-tech audience.
type EmailAuth struct {
	Resolver      Resolver
	DKIMSelectors []string
}

// NewEmailAuth returns an EmailAuth using the system resolver and the default selectors.
func NewEmailAuth() *EmailAuth {
	return &EmailAuth{Resolver: net.DefaultResolver, DKIMSelectors: defaultDKIMSelectors}
}

func (e *EmailAuth) resolver() Resolver {
	if e.Resolver != nil {
		return e.Resolver
	}
	return net.DefaultResolver
}

func (e *EmailAuth) selectors() []string {
	if len(e.DKIMSelectors) > 0 {
		return e.DKIMSelectors
	}
	return defaultDKIMSelectors
}

// FetchDomains resolves the email-auth posture of several domains (deduped, ordered).
func (e *EmailAuth) FetchDomains(ctx context.Context, domains []string) []DomainConfig {
	out := make([]DomainConfig, 0, len(domains))
	for _, d := range dedupeLower(domains) {
		out = append(out, e.FetchDomain(ctx, d))
	}
	return out
}

// FetchDomain resolves one domain. A lookup miss (NXDOMAIN / no record) is not an error —
// it is the finding: "we queried and the record is absent". So a domain with no DMARC
// record returns DMARC="" and checkEmailAuth fires, grounded by the negative lookup.
func (e *EmailAuth) FetchDomain(ctx context.Context, domain string) DomainConfig {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	dc := DomainConfig{Name: domain}
	r := e.resolver()

	// DMARC: _dmarc.<domain>, record with v=DMARC1; p= tag is the policy. pct/sp are depth
	// signals (partial enforcement / subdomain gap).
	if recs, err := r.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		dc.DMARC = parseDMARC(recs)
		if dc.DMARC != "" {
			dc.DMARCPct = dmarcPct(recs)
			dc.DMARCSub = dmarcSubPolicy(recs)
		}
	}
	// SPF: a TXT on the apex starting v=spf1; the `all` qualifier tells us if it's enforcing.
	if recs, err := r.LookupTXT(ctx, domain); err == nil {
		dc.SPF = hasSPF(recs)
		if dc.SPF {
			dc.SPFAll = spfAllQualifier(recs)
		}
	}
	// DKIM: any known selector publishing a v=DKIM1 / p= record.
	for _, sel := range e.selectors() {
		recs, err := r.LookupTXT(ctx, sel+"._domainkey."+domain)
		if err == nil && hasDKIM(recs) {
			dc.DKIM = true
			break
		}
	}
	return dc
}

// parseDMARC returns the policy ("reject" | "quarantine" | "none") from a DMARC record
// set, or "" when no valid DMARC record / no p= tag is present.
func parseDMARC(recs []string) string {
	for _, rec := range recs {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=dmarc1") {
			continue
		}
		for _, tag := range strings.Split(rec, ";") {
			tag = strings.TrimSpace(tag)
			if v, ok := strings.CutPrefix(strings.ToLower(tag), "p="); ok {
				switch p := strings.TrimSpace(v); p {
				case "reject", "quarantine", "none":
					return p
				}
			}
		}
	}
	return ""
}

func hasSPF(recs []string) bool {
	for _, rec := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=spf1") {
			return true
		}
	}
	return false
}

// spfAllQualifier returns the qualifier on the SPF `all` mechanism: "-" (fail, strict), "~"
// (softfail), "?" (neutral), "+" (pass — permits anyone). "" when there is no `all` mechanism.
// "+" and "?" are permissive: they defeat SPF by letting any sender pass.
func spfAllQualifier(recs []string) string {
	for _, rec := range recs {
		l := strings.ToLower(strings.TrimSpace(rec))
		if !strings.HasPrefix(l, "v=spf1") {
			continue
		}
		for _, tok := range strings.Fields(l) {
			switch tok {
			case "-all":
				return "-"
			case "~all":
				return "~"
			case "?all":
				return "?"
			case "+all", "all":
				return "+" // a bare `all` mechanism defaults to the "+" (pass) qualifier
			}
		}
	}
	return ""
}

// dmarcPct returns the DMARC pct= value (the % of mail the policy is applied to). Defaults to
// 100 when a DMARC record is present without an explicit pct (the RFC default).
func dmarcPct(recs []string) int {
	for _, rec := range recs {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=dmarc1") {
			continue
		}
		for _, tag := range strings.Split(rec, ";") {
			if v, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(tag)), "pct="); ok {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 && n <= 100 {
					return n
				}
			}
		}
		return 100 // DMARC present, no explicit pct → RFC default
	}
	return 0
}

// dmarcSubPolicy returns the DMARC sp= (subdomain policy) value, or "" when absent (subdomains
// then inherit the main p= policy).
func dmarcSubPolicy(recs []string) string {
	for _, rec := range recs {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=dmarc1") {
			continue
		}
		for _, tag := range strings.Split(rec, ";") {
			if v, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(tag)), "sp="); ok {
				switch p := strings.TrimSpace(v); p {
				case "reject", "quarantine", "none":
					return p
				}
			}
		}
	}
	return ""
}

func hasDKIM(recs []string) bool {
	for _, rec := range recs {
		l := strings.ToLower(rec)
		if strings.Contains(l, "v=dkim1") || strings.Contains(l, "p=") {
			return true
		}
	}
	return false
}

// DomainsFromUsers derives the org's sending domains from its user emails (the part after
// @), deduped + sorted. Grounded + zero-config: the domains a workspace actually sends
// from are exactly its users' domains, no extra API/directory call needed.
func DomainsFromUsers(users []User) []string {
	var domains []string
	for _, u := range users {
		if at := strings.LastIndex(u.Email, "@"); at >= 0 && at < len(u.Email)-1 {
			domains = append(domains, u.Email[at+1:])
		}
	}
	return dedupeLower(domains)
}

func dedupeLower(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
