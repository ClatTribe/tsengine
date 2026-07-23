package osint

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// hudsonrock.go is the KEYLESS dark-web / infostealer collector — the single biggest external-exposure
// gap (StealerLog was a modeled type with NO feed behind it). HudsonRock's Cavalier "search-by-domain"
// API is free + keyless: given a domain it returns the infostealer infections that captured a credential
// for that domain — the exact SpyCloud/Flare dark-web-monitoring signal (a corporate credential harvested
// by RedLine/Lumma/Vidar/etc., the highest-severity OSINT class). Plain HTTPS JSON, so it runs host-side
// (SSRF-screened in the caller) like the crt.sh collector; the parser is pure + tested, the live fetch is
// best-effort. The other dark-web feeds (Flare/Intel471/SpyCloud/DeHashed) stay the credential-gated half.
//
// Grounding (§10): every emitted StealerLog is a real infection the API returned for the queried domain
// (the query itself scopes it to the org), never inferred. A schema mismatch / empty response → zero
// findings, never a crash or an invented credential.

// HudsonRockURL is the keyless Cavalier search-by-domain endpoint.
func HudsonRockURL(domain string) string {
	return "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=" +
		strings.ToLower(strings.TrimSpace(domain))
}

// hrResponse is the slice of the Cavalier response we rely on.
type hrResponse struct {
	Data hrData `json:"data"`
}
type hrData struct {
	Stealers []hrStealer `json:"stealers"`
}
type hrStealer struct {
	StealerFamily   string   `json:"stealer_family"`
	DateCompromised string   `json:"date_compromised"`
	TopLogins       []string `json:"top_logins"`
	TopPasswords    []string `json:"top_passwords"`
}

// ParseHudsonRock turns a Cavalier search-by-domain response into StealerLog entries — one per infection
// the API returned for the queried domain (the query scopes it, so each is a corporate-credential
// compromise for the org). Pure + testable. Email is the org-domain login if the record exposes one
// (best-effort — the free tier may mask it); Password reflects a captured plaintext password. Deduped +
// sorted for determinism.
func ParseHudsonRock(domain string, body []byte) []StealerLog {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || len(body) == 0 {
		return nil
	}
	var resp hrResponse
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	out := make([]StealerLog, 0, len(resp.Data.Stealers))
	seen := map[string]bool{}
	for _, s := range resp.Data.Stealers {
		email := orgLogin(s.TopLogins, domain)
		key := email + "|" + s.StealerFamily + "|" + s.DateCompromised
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, StealerLog{
			Email:    email,
			Domain:   domain,
			Malware:  strings.TrimSpace(s.StealerFamily),
			Date:     firstDate(s.DateCompromised),
			Source:   "hudsonrock",
			Password: len(s.TopPasswords) > 0,
		})
	}
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Email != out[j].Email {
			return out[i].Email < out[j].Email
		}
		return out[i].Date < out[j].Date
	})
	return out
}

// orgLogin returns the first login that belongs to the org's domain (an email @domain, or a login that
// contains the domain), else "" (masked / not exposed — still a grounded infection via the scoped query).
func orgLogin(logins []string, domain string) string {
	for _, l := range logins {
		ll := strings.ToLower(strings.TrimSpace(l))
		if ll == "" {
			continue
		}
		if strings.HasSuffix(ll, "@"+domain) || strings.Contains(ll, domain) {
			return ll
		}
	}
	return ""
}

// firstDate trims a timestamp to its date portion (Cavalier returns RFC3339-ish strings).
func firstDate(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "T "); i > 0 {
		return s[:i]
	}
	return s
}

// CollectStealerLogs runs the keyless HudsonRock collector over the org's domains and returns an OSINT
// Snapshot (StealerLogs) ready for Assess. No API key. Best-effort — a domain's fetch failure never
// aborts the collection.
func CollectStealerLogs(ctx context.Context, org string, domains []string, fetch Fetcher) Snapshot {
	snap := Snapshot{Org: org, Domains: domains}
	seen := map[string]bool{}
	for _, d := range domains {
		body, err := fetch(ctx, HudsonRockURL(d))
		if err != nil {
			continue
		}
		for _, sl := range ParseHudsonRock(d, body) {
			key := sl.Email + "|" + sl.Malware + "|" + sl.Date + "|" + sl.Domain
			if seen[key] {
				continue
			}
			seen[key] = true
			snap.StealerLogs = append(snap.StealerLogs, sl)
		}
	}
	return snap
}
