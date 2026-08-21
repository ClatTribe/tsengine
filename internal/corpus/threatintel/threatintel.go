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
	"sort"
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
	CVSSVector string           `json:"cvss_vector,omitempty"`
	KEV        *types.KEVStatus `json:"kev,omitempty"`
	EPSS       *types.EPSSScore `json:"epss,omitempty"`
	Advisories []string         `json:"advisories,omitempty"`
	Exploits   []string         `json:"exploits,omitempty"`
	// NucleiTemplate is the template file that checks for this CVE, when one exists.
	// Unlike every other field here it is a fact about OUR tooling rather than the world:
	// it answers "can we test for this", which is what stops the probe planner from
	// spending a capped slot on a template nuclei does not have.
	NucleiTemplate string `json:"nuclei_template,omitempty"`
	// WeaponRank is Metasploit's own reliability name for the BEST module targeting this
	// CVE ("excellent" … "manual"). It refines the weaponized rung: a module that never
	// crashes the service and one that needs hand-holding are both "a module exists", and
	// a defender choosing what to patch first should not have to treat them alike.
	WeaponRank string `json:"weapon_rank,omitempty"`
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
	// WeaponizedCount is the CVEs with a Metasploit EXPLOIT module — a strict subset of the
	// exploit-bearing set, reported separately because it is a stronger claim than "a PoC exists".
	WeaponizedCount int `json:"weaponized_count,omitempty"`
	// TemplateCount is the CVEs we can actually probe for. Reported because the ratio to
	// EntryCount is the honest size of what a threat-informed probe plan can reach: the
	// rest of the corpus is CVEs we can rank but not test.
	TemplateCount int       `json:"template_count,omitempty"`
	CVSSCount     int       `json:"cvss_count,omitempty"`
	BuiltAt       time.Time `json:"built_at"`
}

// Build merges the parsed KEV + EPSS + ExploitDB sets into the corpus + manifest. The union is keyed
// by CVE: a CVE may have any subset of {EPSS, KEV, public-exploit refs}. EPSS dominates coverage
// (~250k CVEs); KEV is the high-signal in-the-wild overlay (~1.3k); ExploitDB is the public-exploit-
// exists overlay (the patch-priority signal between EPSS probability and KEV exploitation). A nil
// exploits map is fine — it's a best-effort feed (Refresh keeps going if it can't fetch ExploitDB).
// Sources is everything Build merges, one named field per feed.
//
// IT IS A STRUCT BECAUSE THE POSITIONAL FORM HAD BECOME DANGEROUS. It reached ten
// parameters including THREE adjacent maps — exploits and weaponized are both
// map[string][]string, and templates is map[string]string next to them. Swapping two of
// those compiles, passes every type check, and produces a corpus that is quietly wrong:
// public-exploit refs filed as weaponized ones would promote a proof-of-concept to a
// Metasploit module on every finding that carried it. Named fields make that mistake
// impossible to write rather than merely unlikely.
type Sources struct {
	KEV      map[string]types.KEVStatus
	KEVAsOf  time.Time
	KEVVer   string
	EPSS     map[string]types.EPSSScore
	EPSSAsOf time.Time
	// Exploits is the public-exploit-EXISTS overlay (Exploit-DB); Weaponized is the
	// stronger, separate claim that a Metasploit module exists, with WeaponRank carrying
	// Metasploit's own reliability name for the best one.
	Exploits   map[string][]string
	Weaponized map[string][]string
	WeaponRank map[string]int
	// Templates answers "can WE test for this", which is a fact about us rather than the
	// world — see nuclei.go.
	Templates map[string]string
	CVSS      map[string]NVDEntry
}

// Build merges the parsed feeds into the corpus + manifest.
func Build(src Sources) (map[string]Entry, Manifest) {
	kev, kevAsOf, kevVer := src.KEV, src.KEVAsOf, src.KEVVer
	epss, epssAsOf := src.EPSS, src.EPSSAsOf
	exploits, weaponized, weaponRank := src.Exploits, src.Weaponized, src.WeaponRank
	templates, cvss := src.Templates, src.CVSS

	entries := make(map[string]Entry, len(epss)+len(kev))
	for cve, e := range epss {
		ee := e
		entries[cve] = Entry{EPSS: &ee}
	}
	for cve, k := range kev {
		kk := k
		ent := entries[cve] // zero Entry if EPSS absent
		ent.KEV = &kk
		// Entry.Advisories is the field that already flows through the L1.5 hook onto every
		// finding, and no source had ever written it — the reference URLs sat parsed and
		// discarded in the KEV notes. Filling it here rather than adding a Build parameter
		// keeps them where they came from: they ARE this KEV entry's references.
		if len(kk.Advisories) > 0 {
			ent.Advisories = kk.Advisories
		}
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
	// Metasploit modules ride the SAME Exploits list rather than a new field: the refs are
	// self-describing ("metasploit:exploit/..." vs "exploitdb:EDB-..."), so the dashboard contract
	// gains nothing to version and a consumer that cares can tell them apart. The distinction is
	// surfaced where it changes a decision — Finding.L15Summary tags `weaponized` separately from
	// `pub-exploit`, because a module an operator can run tonight is a different fact from a
	// proof-of-concept somebody would have to finish first.
	weaponizedCVEs := 0
	for cve, refs := range weaponized {
		if len(refs) == 0 {
			continue
		}
		ent := entries[cve] // zero Entry if KEV/EPSS/ExploitDB absent — a module alone is worth pinning
		ent.Exploits = mergeRefs(ent.Exploits, refs)
		ent.WeaponRank = RankName(weaponRank[cve])
		entries[cve] = ent
		weaponizedCVEs++
	}
	// Nuclei template availability. Only recorded for CVEs the corpus already knows about
	// OR that a template exists for — an entry carrying nothing but a template path is
	// still worth pinning, because "we can check this" is a useful fact even about a CVE
	// with no EPSS score.
	templateCVEs := 0
	for cve, path := range templates {
		if path == "" {
			continue
		}
		ent := entries[cve]
		ent.NucleiTemplate = path
		entries[cve] = ent
		templateCVEs++
	}
	// NVD CVSS base vectors: enrich coverage with attack-vector detail. A CVE with only CVSS (no KEV/EPSS/
	// exploit) is still worth pinning — the vector drives surface_priority/exploitability reasoning. We only
	// overwrite the base score from NVD when the entry had none (KEV/EPSS don't carry one today, so this is
	// the source that populates CVSS), and always attach the vector.
	cvssCVEs := 0
	for cve, n := range cvss {
		if strings.TrimSpace(n.Vector) == "" {
			continue
		}
		ent := entries[cve]
		if ent.CVSS == 0 {
			ent.CVSS = n.BaseScore
		}
		ent.CVSSVector = n.Vector
		entries[cve] = ent
		cvssCVEs++
	}
	sources := []string{KEVURL, EPSSURL}
	if exploitCVEs > 0 {
		sources = append(sources, ExploitDBURL)
	}
	if weaponizedCVEs > 0 {
		sources = append(sources, MetasploitURL)
	}
	if templateCVEs > 0 {
		sources = append(sources, NucleiTemplatesURL)
	}
	if cvssCVEs > 0 {
		sources = append(sources, NVDURL)
	}
	m := Manifest{
		Version:         fmt.Sprintf("kev-%s+epss-%s", sanitize(kevVer), epssAsOf.UTC().Format("2006-01-02")),
		KEVAsOf:         kevAsOf.UTC(),
		EPSSAsOf:        epssAsOf.UTC(),
		Sources:         sources,
		EntryCount:      len(entries),
		KEVCount:        len(kev),
		EPSSCount:       len(epss),
		ExploitCount:    exploitCVEs,
		WeaponizedCount: weaponizedCVEs,
		TemplateCount:   templateCVEs,
		CVSSCount:       cvssCVEs,
		BuiltAt:         time.Now().UTC(),
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

// mergeRefs unions two exploit-ref lists, sorted and deduped. Sorted because the corpus is
// diffed between refreshes and map-order output would make every rebuild look like a change;
// deduped because the same ref arriving from two feeds is one artifact, not two.
func mergeRefs(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	out := append(append([]string{}, a...), b...)
	sort.Strings(out)
	return dedupeStrings(out)
}
