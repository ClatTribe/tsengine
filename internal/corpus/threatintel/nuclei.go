package threatintel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// NucleiTemplatesURL is the nuclei-templates project's own CVE index — one JSON object per
// line, each naming a CVE and the template file that checks for it. Free, no API key, one
// GET, maintained by the project.
//
// THIS IS A DIFFERENT KIND OF FACT FROM THE OTHER FEEDS, and the difference is the point.
// KEV, EPSS, Exploit-DB and Metasploit all describe the WORLD: how likely this is to be
// attacked, whether anyone has, whether a weapon exists. This one describes US: whether we
// can actually check for it.
//
// It matters because the threat-informed probe plan (internal/threatinformed) assumed
// nuclei has a template for every CVE it selects — it sets TemplateID to the CVE id, since
// that is how nuclei names them. For the ~4.3k CVEs with a template that is right. For
// every other CVE in a ~250k-entry corpus, `-id CVE-…` matches nothing and the probe does
// nothing. The plan is CAPPED, so each of those silently displaces a probe that would have
// run — a high-priority KEV CVE with no template pushes out a lower-priority one that could
// have been tested.
//
// The second consequence is the one that matters more: without this, a KEV CVE matching an
// observed product just vanishes from the plan, and the customer reads a clean probe report
// as "we checked everything that matters". Knowing which CVEs we CANNOT test is what lets
// the plan say so instead.
const NucleiTemplatesURL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"

// nucleiTemplate is the slice of an index line this needs. Everything else (severity,
// description, authors, references) is ignored so an upstream schema addition cannot break
// the parse.
type nucleiTemplate struct {
	ID       string `json:"ID"`
	FilePath string `json:"file_path"`
}

// ParseNucleiTemplates reads the JSON-lines CVE index into a CVE→template-path map.
//
// Line-delimited, not an array, so it is streamed: the file is a couple of megabytes today
// and there is no reason for the whole thing to be resident. A malformed line is SKIPPED
// rather than failing the parse — one bad record upstream should cost one template, not the
// entire availability index, and losing the index entirely would put the plan straight back
// to assuming every CVE is testable.
func ParseNucleiTemplates(r io.Reader) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxNucleiLine)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var t nucleiTemplate
		if json.Unmarshal([]byte(line), &t) != nil {
			continue
		}
		id := strings.ToUpper(strings.TrimSpace(t.ID))
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		path := strings.TrimSpace(t.FilePath)
		if path == "" {
			// A template we cannot name is not one we can pass to nuclei. Recording the
			// CVE as available with an empty path would restore exactly the bug this
			// index exists to fix, one entry at a time.
			continue
		}
		out[id] = path
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("threatintel: read nuclei template index: %w", err)
	}
	return out, nil
}

// maxNucleiLine bounds one index line. Entries carry a description and a reference list;
// 1 MiB is far beyond any real one and stops a hostile or corrupt feed from growing the
// scanner buffer without limit.
const maxNucleiLine = 1 << 20
