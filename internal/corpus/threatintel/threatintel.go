// Package threatintel ingests authoritative OSINT vulnerability feeds into
// the versioned, on-disk threat-intel corpus the L1.5 threat_intel hook (and
// the L2 query_threat_intel tool) read.
//
// Sources (KEV+EPSS scope):
//   - CISA KEV  — Known Exploited Vulnerabilities catalog (the "actively
//     exploited" signal; starts compliance SLA clocks). Free JSON, no key.
//   - FIRST.org EPSS — Exploit Prediction Scoring System (the patch-priority
//     signal). Free daily CSV, no key.
//
// The ingestion runs OUT OF BAND (the L0 cron refresh, CLAUDE.md §5) — it is
// NOT a live per-query API call (that's strix's non-reproducible model). It
// snapshots the feeds into <dir>/threat_intel.json + a sidecar manifest; each
// scan then PINS that snapshot version (CLAUDE.md §10). Reproducible OSINT.
package threatintel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Feed source URLs (free, no API key).
const (
	KEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	EPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
)

// Entry is one CVE's intel. JSON tags match the L1.5 hook's corpus entry, so
// the data file is byte-compatible with the embedded snapshot (a bare
// map[CVE]Entry) — the hook can load either with the same unmarshal.
type Entry struct {
	CVSS       float64          `json:"cvss,omitempty"`
	KEV        *types.KEVStatus `json:"kev,omitempty"`
	EPSS       *types.EPSSScore `json:"epss,omitempty"`
	Advisories []string         `json:"advisories,omitempty"`
	Exploits   []string         `json:"exploits,omitempty"`
}

// Manifest is the cheap-to-read provenance sidecar (no entries). resolveCorpus
// reads it to stamp the scan's corpus block without parsing the full corpus.
type Manifest struct {
	Version      string    `json:"version"`
	KEVAsOf      time.Time `json:"kev_as_of"`
	EPSSAsOf     time.Time `json:"epss_as_of"`
	Sources      []string  `json:"sources"`
	EntryCount   int       `json:"entry_count"`
	KEVCount     int       `json:"kev_count"`
	EPSSCount    int       `json:"epss_count"`
	ExploitCount int       `json:"exploit_count,omitempty"`
	BuiltAt      time.Time `json:"built_at"`
}

// Build merges the parsed KEV + EPSS + ExploitDB sets into the corpus + manifest. The union is keyed
// by CVE: a CVE may have any subset of {EPSS, KEV, public-exploit refs}. EPSS dominates coverage
// (~250k CVEs); KEV is the high-signal in-the-wild overlay (~1.3k); ExploitDB is the public-exploit-
// exists overlay (the patch-priority signal between EPSS probability and KEV exploitation). A nil
// exploits map is fine — it's a best-effort feed (Refresh keeps going if it can't fetch ExploitDB).
func Build(kev map[string]types.KEVStatus, kevAsOf time.Time, kevVer string,
	epss map[string]types.EPSSScore, epssAsOf time.Time, exploits map[string][]string) (map[string]Entry, Manifest) {

	entries := make(map[string]Entry, len(epss)+len(kev))
	for cve, e := range epss {
		ee := e
		entries[cve] = Entry{EPSS: &ee}
	}
	for cve, k := range kev {
		kk := k
		ent := entries[cve] // zero Entry if EPSS absent
		ent.KEV = &kk
		entries[cve] = ent
	}
	exploitCVEs := 0
	for cve, refs := range exploits {
		if len(refs) == 0 {
			continue
		}
		ent := entries[cve] // zero Entry if KEV/EPSS absent — a public exploit alone is still worth pinning
		ent.Exploits = refs
		entries[cve] = ent
		exploitCVEs++
	}
	sources := []string{KEVURL, EPSSURL}
	if exploitCVEs > 0 {
		sources = append(sources, ExploitDBURL)
	}
	m := Manifest{
		Version:      fmt.Sprintf("kev-%s+epss-%s", sanitize(kevVer), epssAsOf.UTC().Format("2006-01-02")),
		KEVAsOf:      kevAsOf.UTC(),
		EPSSAsOf:     epssAsOf.UTC(),
		Sources:      sources,
		EntryCount:   len(entries),
		KEVCount:     len(kev),
		EPSSCount:    len(epss),
		ExploitCount: exploitCVEs,
		BuiltAt:      time.Now().UTC(),
	}
	return entries, m
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return strings.ReplaceAll(s, " ", "_")
}

// DataFileName / manifestFor locate the two files in a corpus dir.
const DataFileName = "threat_intel.json"

// ManifestPath returns the sidecar manifest path for a corpus data file.
func ManifestPath(dataPath string) string {
	return strings.TrimSuffix(dataPath, ".json") + ".manifest.json"
}

// Write persists the corpus (bare map[CVE]Entry, keys sorted by json) plus
// the sidecar manifest into dir. Returns the data-file path.
func Write(dir string, entries map[string]Entry, m Manifest) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dataPath := filepath.Join(dir, DataFileName)
	data, err := json.MarshalIndent(entries, "", " ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		return "", err
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(ManifestPath(dataPath), mb, 0o600); err != nil {
		return "", err
	}
	return dataPath, nil
}

// LoadManifest reads the sidecar manifest for a corpus data file (cheap —
// used to stamp the scan's corpus block).
func LoadManifest(dataPath string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(ManifestPath(dataPath)) //nolint:gosec // operator-provided corpus path
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("threatintel: parse manifest: %w", err)
	}
	return m, nil
}
