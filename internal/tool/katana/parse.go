package katana

import (
	"bufio"
	"bytes"
	"encoding/json"
	"sort"
)

// event mirrors katana's -jsonl output. katana emits one JSON object per
// crawled request; the endpoint URL is at request.endpoint.
type event struct {
	Request struct {
		Endpoint string `json:"endpoint"`
		Method   string `json:"method"`
	} `json:"request"`
	// Older/alternate katana builds put the URL at the top level.
	URL string `json:"url"`
}

// parse extracts the unique set of discovered URLs from katana's JSONL
// output. Deduped + sorted for deterministic surface ordering (the
// reproducibility invariant, CLAUDE.md §10).
func parse(blob []byte) []string {
	if len(blob) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(bytes.NewReader(blob))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev event
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		u := ev.Request.Endpoint
		if u == "" {
			u = ev.URL
		}
		if u != "" {
			seen[u] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}
