package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// MetasploitURL is the Metasploit Framework's own module metadata cache — one JSON object
// keyed by module path, each carrying the module's references. Free, no API key, one GET;
// msfconsole ships it for search, so it is maintained by the project rather than scraped.
//
// WHY THIS IS A DIFFERENT SIGNAL FROM EXPLOIT-DB, and not a louder version of it.
//
// Exploit-DB answers "does a public exploit exist" — usually a proof-of-concept, often
// written against one target build, frequently needing a shellcode swap or an offset
// recalculated before it does anything. That is a real signal and it is where
// `pub-exploit` comes from.
//
// A Metasploit module answers a harder question: is this WEAPONIZED. A module is
// `use exploit/...`, `set RHOSTS`, `run` — target selection, payload staging, session
// handling and cleanup already solved by someone else, usable by an operator who could not
// write the exploit and does not need to understand it. The gap between those two is the
// gap between "someone capable could" and "anyone can, tonight", and for deciding what to
// patch first that difference is the whole question.
//
// So it is a rung of its own between pub-exploit and KEV: more weaponized than a PoC, and
// still not evidence of exploitation in the wild, which is what KEV alone means.
const MetasploitURL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

// msfModule is the slice of a module's metadata this needs. The file carries far more
// (targets, platform, rank, disclosure date); everything else is deliberately ignored so a
// schema addition upstream cannot break the parse.
type msfModule struct {
	FullName   string   `json:"fullname"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	References []string `json:"references"`
}

// msfCVERef matches the two forms the references list uses for a CVE: the bare
// "CVE-2021-44228", and Metasploit's own "CVE-2021-44228" prefixed style. URL references
// are ignored — a link to an advisory that happens to contain a CVE id is not the module
// declaring it exploits that CVE, and treating it as one would credit a module with every
// CVE mentioned in a blog post it links to.
var msfCVERef = regexp.MustCompile(`^(?:CVE-)?(\d{4}-\d{4,7})$`)

// ParseMetasploit reads the module metadata into a CVE→[]module-ref map (refs are
// "metasploit:<module path>").
//
// Two decisions worth stating, because both narrow what counts:
//
//   - AUXILIARY AND POST MODULES ARE EXCLUDED. Metasploit's `auxiliary` tree is scanners,
//     fuzzers and credential checkers; `post` runs after you already have a session.
//     Neither weaponizes the CVE, and counting them would put a version-detection scanner
//     on the same rung as a remote-code-execution module. Only `exploit` counts.
//   - A REFERENCE MUST BE A CVE ID, not a URL containing one. See msfCVERef.
func ParseMetasploit(r io.Reader) (map[string][]string, error) {
	var raw map[string]msfModule
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("threatintel: decode Metasploit module metadata: %w", err)
	}
	out := make(map[string][]string)
	for _, m := range raw {
		if !strings.EqualFold(strings.TrimSpace(m.Type), "exploit") {
			continue
		}
		path := strings.TrimSpace(m.FullName)
		if path == "" {
			path = strings.TrimSpace(m.Name)
		}
		if path == "" {
			continue
		}
		for _, ref := range m.References {
			mm := msfCVERef.FindStringSubmatch(strings.TrimSpace(ref))
			if mm == nil {
				continue
			}
			cve := "CVE-" + mm[1]
			out[cve] = append(out[cve], "metasploit:"+path)
		}
	}
	// Deterministic order: the corpus is diffed between refreshes, and map iteration would
	// make every rebuild look like a change to every CVE a module touches.
	for cve, refs := range out {
		sort.Strings(refs)
		out[cve] = dedupeStrings(refs)
	}
	return out, nil
}

// dedupeStrings removes repeats from a sorted slice. A module can list the same CVE twice
// (both reference styles), and a doubled ref would read as two separate weapons.
func dedupeStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
