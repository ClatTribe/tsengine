package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// kevFeed is the subset of the CISA KEV JSON we consume.
type kevFeed struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Vulnerabilities []struct {
		CveID string `json:"cveID"`
		// vendorProject + product name the AFFECTED TECHNOLOGY. Retained (they
		// were previously dropped) because they are what makes threat-informed
		// TARGETING possible: a recon-detected product can be matched against
		// the KEV catalog to probe the CVEs actually exploited in the wild for
		// that technology, instead of a static template list. See
		// internal/threatinformed.
		VendorProject string `json:"vendorProject"`
		Product       string `json:"product"`
		DateAdded     string `json:"dateAdded"` // "2006-01-02"
		// DueDate is CISA's own BOD 22-01 remediation deadline FOR THIS CVE. We
		// previously computed a uniform window from DateAdded; CISA publishes the
		// real per-CVE date, and a deadline the authority actually set beats one we
		// derived.
		DueDate string `json:"dueDate"` // "2006-01-02"
		// KnownRansomwareCampaignUse is "Known" or "Unknown". It is the strongest
		// free prioritisation signal published anywhere: KEV says "exploited in the
		// wild", this says "exploited BY RANSOMWARE CREWS", and the second is what
		// turns a patch window from a quarter into a weekend. It was being dropped,
		// exactly as vendorProject/product were before them.
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		// Notes is a " ; "-separated list of reference URLs, occasionally with a label
		// prefix ("BOD 26-04: https://..."). Non-empty on every entry in the catalog.
		Notes string `json:"notes"`
	} `json:"vulnerabilities"`
}

// ParseKEV reads the CISA KEV JSON feed into a CVE→KEVStatus map. asOf is the
// catalog's dateReleased; version is catalogVersion (for the corpus version
// string). Every listed CVE is, by definition, Listed=true.
func ParseKEV(r io.Reader) (map[string]types.KEVStatus, time.Time, string, error) {
	var feed kevFeed
	if err := json.NewDecoder(r).Decode(&feed); err != nil {
		return nil, time.Time{}, "", fmt.Errorf("threatintel: parse KEV: %w", err)
	}
	out := make(map[string]types.KEVStatus, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		if v.CveID == "" {
			continue
		}
		st := types.KEVStatus{Listed: true, Vendor: v.VendorProject, Product: v.Product,
			Advisories: advisoriesFromNotes(v.Notes)}
		if v.DateAdded != "" {
			if d, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
				st.DateAdded = d.UTC()
			}
		}
		if v.DueDate != "" {
			if d, err := time.Parse("2006-01-02", v.DueDate); err == nil {
				st.DueDate = d.UTC()
			}
		}
		// ONLY the literal "Known" means known. CISA writes "Unknown" for the
		// majority, and treating any non-empty value as a yes would mark most of the
		// catalog as ransomware-linked — the alarm that teaches a team to ignore
		// alarms.
		st.Ransomware = strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known")
		out[v.CveID] = st
	}
	asOf := parseKEVDate(feed.DateReleased)
	return out, asOf, feed.CatalogVersion, nil
}

// parseKEVDate tolerates the RFC3339-ish dateReleased ("2026-05-29T08:00:00.000Z")
// and falls back to now if unparseable.
func parseKEVDate(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// advisoryURL matches the http(s) references inside a KEV entry's notes field.
//
// Only real URLs are kept. The notes are free text with label prefixes and " ; " separators,
// and storing a fragment of prose as an advisory link would put something in front of a
// responder that does not resolve — worse than the empty list it replaces, because an empty
// list is honestly empty.
var advisoryURL = regexp.MustCompile(`https?://[^\s;,)\]]+`)

// advisoriesFromNotes extracts, dedupes and sorts the reference URLs in a KEV note.
//
// Sorted because the corpus is diffed between refreshes and map/slice order would make every
// rebuild look like a change to every entry. Deduped because the same URL listed twice is one
// advisory.
func advisoriesFromNotes(notes string) []string {
	found := advisoryURL.FindAllString(notes, -1)
	if len(found) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(found))
	out := make([]string, 0, len(found))
	for _, u := range found {
		u = strings.TrimRight(u, ".")
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}
