package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MetasploitURL is the Metasploit Framework module-metadata index — a single JSON object mapping every
// module (fullname) to its metadata, including the CVE(s) it weaponizes. Free, no API key. The presence
// of a CVE here is the STRONGEST public-exploit rung below KEV: not just "a PoC exists" (ExploitDB) but
// "a point-and-click, framework-weaponized exploit module exists" — the signal a defender uses to jump a
// patch to the front of the queue. Complements ExploitDB (many CVEs have an MSF module but no EDB entry,
// and vice-versa), so the two together give a fuller weaponization picture than either alone.
const MetasploitURL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

// msfCVERe extracts a CVE id from a bare reference string (the modern Metasploit format is a string like
// "CVE-2017-0144"). The [][]string / ["CVE","2017-0144"] pair form is handled structurally below.
var msfCVERe = regexp.MustCompile(`(?i)CVE-(\d{4})-(\d{3,})`)

// msfModule is the slice of a module's metadata we rely on. References is left as RawMessage because
// Metasploit has used two shapes over time: a flat list of strings ("CVE-2017-0144", "URL-...") and a
// list of [type, value] pairs (["CVE","2017-0144"]). ParseMetasploit handles both.
type msfModule struct {
	FullName   string          `json:"fullname"`
	Type       string          `json:"type"`
	References json.RawMessage `json:"references"`
}

// ParseMetasploit reads modules_metadata_base.json into a CVE→[]ref map (refs are
// "metasploit:<module-fullname>", e.g. "metasploit:exploit/windows/smb/ms17_010_eternalblue"). Pure +
// deterministic (the testable core); the live fetch is best-effort in Refresh (a fetch failure never
// blocks the KEV+EPSS refresh, mirroring ExploitDB). A module that references several CVEs contributes a
// ref to each; a CVE referenced by several modules accumulates all their refs (deduped, order-stable).
func ParseMetasploit(r io.Reader) (map[string][]string, error) {
	var mods map[string]msfModule
	if err := json.NewDecoder(r).Decode(&mods); err != nil {
		return nil, fmt.Errorf("threatintel: decode Metasploit metadata: %w", err)
	}
	out := map[string][]string{}
	seen := map[string]map[string]bool{}
	add := func(cve, ref string) {
		if seen[cve] == nil {
			seen[cve] = map[string]bool{}
		}
		if !seen[cve][ref] {
			seen[cve][ref] = true
			out[cve] = append(out[cve], ref)
		}
	}
	for key, m := range mods {
		name := strings.TrimSpace(m.FullName)
		if name == "" {
			name = key
		}
		ref := "metasploit:" + name
		for _, cve := range cvesFromReferences(m.References) {
			add(cve, ref)
		}
	}
	return out, nil
}

// cvesFromReferences pulls the CVE ids out of a module's references, tolerating both the flat-string and
// the [type,value]-pair shapes. Non-CVE references (URL-, BID-, EDB-, …) are ignored.
func cvesFromReferences(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	push := func(cve string) {
		if cve != "" && !seen[cve] {
			seen[cve] = true
			out = append(out, cve)
		}
	}
	// try the flat-string shape first: ["CVE-2017-0144", "URL-...", ...]
	var strs []string
	if json.Unmarshal(raw, &strs) == nil {
		for _, s := range strs {
			if m := msfCVERe.FindStringSubmatch(s); m != nil {
				push("CVE-" + m[1] + "-" + m[2])
			}
		}
		return out
	}
	// else the [type,value]-pair shape: [["CVE","2017-0144"], ["URL","..."]]
	var pairs [][]string
	if json.Unmarshal(raw, &pairs) == nil {
		for _, p := range pairs {
			if len(p) >= 2 && strings.EqualFold(strings.TrimSpace(p[0]), "CVE") {
				if m := msfCVERe.FindStringSubmatch("CVE-" + strings.TrimSpace(p[1])); m != nil {
					push("CVE-" + m[1] + "-" + m[2])
				}
			}
		}
	}
	return out
}

// mergeExploitRefs unions two CVE→refs maps (order-stable, deduped) — used by Refresh to combine the
// ExploitDB and Metasploit weaponization overlays into the single Exploits set Build consumes.
func mergeExploitRefs(dst, src map[string][]string) map[string][]string {
	if dst == nil {
		dst = map[string][]string{}
	}
	for cve, refs := range src {
		existing := map[string]bool{}
		for _, r := range dst[cve] {
			existing[r] = true
		}
		for _, r := range refs {
			if !existing[r] {
				existing[r] = true
				dst[cve] = append(dst[cve], r)
			}
		}
	}
	return dst
}
