// Package opencre cross-references tsengine's in-house CWE→control compliance crosswalk
// (internal/tracer/hooks/data/compliance.json) against OpenCRE — OWASP's Open Common Requirement Enumeration,
// the leading OSS effort linking CWEs to security standards.
//
// WHY a cross-reference, not a replacement: OpenCRE maps a CWE to CRE NODES (one hop), and CRE nodes link to
// frameworks (NIST 800-53, ISO 27001, PCI DSS, ASVS, …) separately — there is no direct CWE→control edge, and
// OpenCRE does NOT cover SOC 2 / HIPAA / GDPR / CCPA at all. So OpenCRE can't replace our crosswalk for the 22
// frameworks we map. What it CAN do is give each of our hand-curated CWE mappings an auditable OSS PROVENANCE
// signal: "this CWE is recognized by OpenCRE and grounds to N CRE requirement(s)". An auditor can then follow
// CWE → our controls AND CWE → OpenCRE CRE → the same standards, cross-checking our work.
//
// This is the §10 spirit applied to the compliance layer: the mapping stays in-house (§8 annotation, not
// detection — §13 governs detection only), but its provenance becomes traceable to an OSS reference instead of
// being purely asserted. Live fetch is out-of-band (the OpenCRE REST API, like the threat-intel corpus refresh);
// this package is the parser + cross-check, unit-testable offline.
package opencre

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// StandardCWEURL is OpenCRE's REST endpoint listing the CWE standard and its links to CRE nodes. Keyless, public.
// Paginated (?page=N) — a refresh walks total_pages. Free, no API key (like the KEV/EPSS/ExploitDB feeds).
const StandardCWEURL = "https://www.opencre.org/rest/v1/standard/CWE"

// CRELink is one OpenCRE CRE requirement a CWE grounds to.
type CRELink struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// standardsPage mirrors the verified OpenCRE /rest/v1/standard/CWE response shape.
type standardsPage struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
	Standards  []struct {
		SectionID string `json:"sectionID"` // the bare CWE number, e.g. "319"
		Links     []struct {
			LType    string `json:"ltype"`
			Document struct {
				DocType string `json:"doctype"` // "CRE" for a requirement node
				ID      string `json:"id"`
				Name    string `json:"name"`
			} `json:"document"`
		} `json:"links"`
	} `json:"standards"`
}

// ParseStandard reads one OpenCRE CWE-standard page into a CWE-number → CRE links map (only the CRE links are
// kept; non-CRE link types are ignored). Keys are the canonical "CWE-<n>" form so they match our crosswalk.
// Merge pages by calling it per page and unioning (a CWE can appear on one page only, but be defensive).
func ParseStandard(r io.Reader) (map[string][]CRELink, error) {
	p, err := decodePage(r)
	if err != nil {
		return nil, err
	}
	return p.toMap(), nil
}

func decodePage(r io.Reader) (standardsPage, error) {
	var p standardsPage
	err := json.NewDecoder(r).Decode(&p)
	return p, err
}

func (p standardsPage) toMap() map[string][]CRELink {
	out := make(map[string][]CRELink)
	for _, s := range p.Standards {
		num := strings.TrimSpace(s.SectionID)
		if num == "" {
			continue
		}
		key := "CWE-" + num
		for _, l := range s.Links {
			if !strings.EqualFold(l.Document.DocType, "CRE") || strings.TrimSpace(l.Document.ID) == "" {
				continue
			}
			out[key] = appendUniqueCRE(out[key], CRELink{ID: l.Document.ID, Name: l.Document.Name})
		}
	}
	return out
}

// Fetch walks every page of OpenCRE's CWE standard endpoint and returns the merged CWE→CRE map. Out-of-band
// (the auditor/CLI calls it, not a scan) — like the threat-intel corpus refresh. Best-effort per page: a page
// that fails to fetch/decode is skipped, never aborting the whole walk. Bounded by a hard page cap so a bad
// total_pages can't loop forever.
func Fetch(ctx context.Context, c *http.Client) (map[string][]CRELink, error) {
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	merged := make(map[string][]CRELink)
	const maxPages = 100
	total := 1
	for page := 1; page <= total && page <= maxPages; page++ {
		p, err := fetchPage(ctx, c, page)
		if err != nil {
			if page == 1 {
				return nil, err // first page failing is a hard error (endpoint down / changed)
			}
			continue // later page hiccup: skip, keep what we have
		}
		if p.TotalPages > total {
			total = p.TotalPages
		}
		for cwe, links := range p.toMap() {
			for _, l := range links {
				merged[cwe] = appendUniqueCRE(merged[cwe], l)
			}
		}
	}
	return merged, nil
}

func fetchPage(ctx context.Context, c *http.Client, page int) (standardsPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?page=%d", StandardCWEURL, page), nil)
	if err != nil {
		return standardsPage{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return standardsPage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return standardsPage{}, fmt.Errorf("opencre: GET page %d: status %d", page, resp.StatusCode)
	}
	return decodePage(resp.Body)
}

// ProvenanceReport is the cross-check of our crosswalk against OpenCRE: which of our mapped CWEs are corroborated
// by an OpenCRE CRE node (OSS-traceable provenance) vs in-house-only (no OpenCRE nexus — honest, not a defect:
// OpenCRE simply may not cover that CWE).
type ProvenanceReport struct {
	TotalMapped   int      `json:"total_mapped"`   // CWEs in our crosswalk
	OpenCREBacked []string `json:"opencre_backed"` // ours that OpenCRE also recognizes (≥1 CRE link)
	InHouseOnly   []string `json:"in_house_only"`  // ours with no OpenCRE CRE coverage
	BackedPercent int      `json:"backed_percent"` // OpenCRE-backed share, 0–100
}

// CrossReference reports how much of our crosswalk OpenCRE corroborates. ourCWEs is the set of CWE keys from
// compliance.json; openCRE is the parsed CWE→CRE map. Grounded (§10): it reports the real overlap, never claims
// OpenCRE backs a mapping it doesn't.
func CrossReference(ourCWEs []string, openCRE map[string][]CRELink) ProvenanceReport {
	rep := ProvenanceReport{TotalMapped: len(ourCWEs)}
	for _, cwe := range ourCWEs {
		if len(openCRE[strings.ToUpper(strings.TrimSpace(cwe))]) > 0 {
			rep.OpenCREBacked = append(rep.OpenCREBacked, cwe)
		} else {
			rep.InHouseOnly = append(rep.InHouseOnly, cwe)
		}
	}
	sort.Strings(rep.OpenCREBacked)
	sort.Strings(rep.InHouseOnly)
	if rep.TotalMapped > 0 {
		rep.BackedPercent = 100 * len(rep.OpenCREBacked) / rep.TotalMapped
	}
	return rep
}

func appendUniqueCRE(xs []CRELink, v CRELink) []CRELink {
	for _, x := range xs {
		if x.ID == v.ID {
			return xs
		}
	}
	return append(xs, v)
}
