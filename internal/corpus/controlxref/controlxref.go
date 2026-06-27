// Package controlxref cross-references tsengine's in-house CWE→control compliance crosswalk against the
// authoritative OSS control-cross-mapping catalogs — the Secure Controls Framework (SCF) and the CSA Cloud
// Controls Matrix (CCM). These complement OpenCRE (`internal/corpus/opencre`), which keys on CWE but does NOT
// cover SOC 2 / HIPAA / GDPR / CCPA: SCF and CCM key on CONTROL↔FRAMEWORK and DO cover those, so they corroborate
// the part of our crosswalk OpenCRE can't.
//
// Both SCF and CCM are distributed as a MATRIX export (one row per meta-control; one column per framework; each
// cell holds that framework's control IDs that map to the row). This package parses that shared shape and, for
// each framework we map, reports how many of OUR control IDs appear in the source's mapping — an auditable,
// grounded provenance signal ("control SOC2 CC6.1 is corroborated by SCF"). §10: it reports the REAL overlap and
// never claims a corroboration the data doesn't show; a control we list that the source doesn't is reported
// honestly as either a format difference or genuinely in-house, never hidden.
//
// SCF (CC BY-ND) and CCM are free but have no clean API, so the export FILE is operator-provided out-of-band
// (like the threat-intel corpus) — the parser + cross-check here are pure and unit-testable.
package controlxref

import (
	"encoding/csv"
	"io"
	"sort"
	"strings"
)

// CrossMap is a parsed source: our-framework-key → the set of (normalized) control IDs the source maps for it.
type CrossMap map[string]map[string]bool

// Source describes how to read a matrix export: per our-framework-key, the header substrings that identify the
// CSV column holding that framework's control IDs (lowercased, matched as substrings → robust to column
// reordering + minor header-text drift across export versions).
type Source struct {
	Name           string
	FrameworkMatch map[string][]string
}

// Parse reads a matrix CSV export into a CrossMap using the source's column-header matching. A cell may carry
// several control IDs (comma / newline / space / semicolon separated). Unknown columns are ignored.
func Parse(r io.Reader, src Source) (CrossMap, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		return nil, err
	}
	// column index → our framework key (first matching framework wins for a column).
	colFW := map[int]string{}
	for i, h := range header {
		hl := strings.ToLower(strings.TrimSpace(h))
		if hl == "" {
			continue
		}
		for fw, pats := range src.FrameworkMatch {
			matched := false
			for _, p := range pats {
				if strings.Contains(hl, p) {
					matched = true
					break
				}
			}
			if matched {
				colFW[i] = fw
				break
			}
		}
	}
	out := CrossMap{}
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // a malformed row never aborts the parse
		}
		for i, fw := range colFW {
			if i >= len(rec) {
				continue
			}
			for _, id := range splitControlIDs(rec[i]) {
				n := normalizeControl(id)
				if n == "" {
					continue
				}
				if out[fw] == nil {
					out[fw] = map[string]bool{}
				}
				out[fw][n] = true
			}
		}
	}
	return out, nil
}

// FrameworkCoverage is one framework's corroboration result.
type FrameworkCoverage struct {
	Framework    string   `json:"framework"`
	Mapped       int      `json:"mapped"`       // controls WE map for this framework
	Corroborated int      `json:"corroborated"` // of ours, how many the source also lists
	Missing      []string `json:"missing,omitempty"`
}

// Report is the cross-check of our crosswalk against one source.
type Report struct {
	Source        string              `json:"source"`
	TotalControls int                 `json:"total_controls"`
	Corroborated  int                 `json:"corroborated"`
	Percent       int                 `json:"percent"`
	Frameworks    []FrameworkCoverage `json:"frameworks"`
}

// CrossReference reports how much of OUR crosswalk the source corroborates. `ours` is our-framework-key →
// the control IDs we map (e.g. from hooks.ControlsFor). Grounded (§10): a control counts as corroborated only
// if the source's data actually lists it (normalized match); the rest is reported as missing, not assumed.
func CrossReference(name string, ours map[string][]string, m CrossMap) Report {
	rep := Report{Source: name}
	fws := make([]string, 0, len(ours))
	for fw := range ours {
		fws = append(fws, fw)
	}
	sort.Strings(fws)
	for _, fw := range fws {
		ctrls := ours[fw]
		if len(ctrls) == 0 {
			continue
		}
		fc := FrameworkCoverage{Framework: fw, Mapped: len(ctrls)}
		for _, c := range ctrls {
			if m[fw][normalizeControl(c)] {
				fc.Corroborated++
			} else {
				fc.Missing = append(fc.Missing, c)
			}
		}
		sort.Strings(fc.Missing)
		rep.TotalControls += fc.Mapped
		rep.Corroborated += fc.Corroborated
		rep.Frameworks = append(rep.Frameworks, fc)
	}
	if rep.TotalControls > 0 {
		rep.Percent = 100 * rep.Corroborated / rep.TotalControls
	}
	return rep
}

func splitControlIDs(cell string) []string {
	return strings.FieldsFunc(cell, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '|'
	})
}

// normalizeControl canonicalizes a control id for comparison: trim, uppercase, drop internal spaces (so
// "CC 6.1" == "CC6.1"). Conservative — it never strips structure that distinguishes two real controls.
func normalizeControl(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// SCF is the Secure Controls Framework export column-matching config. The SCF workbook has one column per
// mapped framework; these substrings identify the columns for the frameworks our crosswalk uses.
var SCF = Source{
	Name: "SCF",
	FrameworkMatch: map[string][]string{
		"soc2":         {"soc 2", "aicpa tsc", "trust services"},
		"iso27001":     {"iso 27001", "iso/iec 27001", "27001"},
		"iso27701":     {"27701"},
		"iso27018":     {"27018"},
		"iso22301":     {"22301"},
		"iso42001":     {"42001"},
		"pci":          {"pci dss", "pci-dss"},
		"hipaa":        {"hipaa"},
		"gdpr":         {"gdpr", "eu gdpr"},
		"ccpa":         {"ccpa", "cpra"},
		"nist_csf":     {"nist csf", "cybersecurity framework"},
		"nist_800_53":  {"800-53"},
		"nist_800_171": {"800-171"},
		"fedramp":      {"fedramp"},
		"cmmc":         {"cmmc"},
		"cis_v8":       {"cis csc", "cis controls", "cis v8"},
		"sox":          {"sox", "sarbanes"},
		"glba":         {"glba", "gramm"},
		"dpdp":         {"dpdp", "india dpdp"},
		"nist_ai_rmf":  {"ai rmf", "nist ai"},
		"eu_ai_act":    {"eu ai act", "ai act"},
		"pipeda":       {"pipeda"},
	},
}

// CCM is the CSA Cloud Controls Matrix export column-matching config (its framework cross-mappings tab).
var CCM = Source{
	Name: "CCM",
	FrameworkMatch: map[string][]string{
		"soc2":        {"soc 2", "aicpa", "trust services"},
		"iso27001":    {"iso/iec 27001", "iso 27001", "27001"},
		"pci":         {"pci dss", "pci-dss"},
		"hipaa":       {"hipaa"},
		"gdpr":        {"gdpr"},
		"nist_csf":    {"nist csf", "cybersecurity framework"},
		"nist_800_53": {"800-53"},
		"fedramp":     {"fedramp"},
		"cis_v8":      {"cis", "ccm"},
	},
}
