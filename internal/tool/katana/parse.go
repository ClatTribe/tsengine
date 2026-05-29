package katana

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"sort"
)

// event mirrors katana's -jsonl output. katana emits one JSON object per
// crawled request; the endpoint URL is at request.endpoint. With -fx
// (form extraction) each event also carries the page's forms.
type event struct {
	Request struct {
		Endpoint string `json:"endpoint"`
		Method   string `json:"method"`
	} `json:"request"`
	// Older/alternate katana builds put the URL at the top level.
	URL string `json:"url"`
	// Forms is katana's -fx output: each form's method, action, and field
	// names. Load-bearing for detection: an app's injectable inputs live in
	// forms whose params are NOT in the crawled URL (a bare /case.jsp with a
	// POST form). We synthesize a GET param URL from each so the injection
	// tools (sqlmap/dalfox/nuclei -dast) get an injection point — they fan
	// only on param-bearing URLs. (Targets like WAVSEP accept the param via
	// GET even when the form method is POST.)
	Forms []struct {
		Method     string   `json:"method"`
		Action     string   `json:"action"`
		Parameters []string `json:"parameters"`
	} `json:"forms"`
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
		base := ev.Request.Endpoint
		if base == "" {
			base = ev.URL
		}
		if base != "" {
			seen[base] = struct{}{}
		}
		// Synthesize an injectable GET URL from each extracted form so the
		// fan-out's injection tools get an injection point (the WAVSEP/most-
		// apps gap: params live in forms, not in crawled URLs).
		for _, f := range ev.Forms {
			if fu := formParamURL(base, f.Action, f.Parameters); fu != "" {
				seen[fu] = struct{}{}
			}
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

// formParamURL turns a form (action + field names) into a single injectable
// GET URL: action?field1=1&field2=1. A relative action is resolved against
// the page it was found on. Returns "" if there's nothing injectable.
// Query keys are sorted (url.Values.Encode) for deterministic surface
// ordering (reproducibility, §10). The seed value "1" is a placeholder the
// injection tools replace with their payloads.
func formParamURL(pageURL, action string, params []string) string {
	if len(params) == 0 {
		return ""
	}
	act := action
	if act == "" {
		act = pageURL
	}
	u, err := url.Parse(act)
	if err != nil {
		return ""
	}
	if !u.IsAbs() && pageURL != "" {
		if base, berr := url.Parse(pageURL); berr == nil {
			u = base.ResolveReference(u)
		}
	}
	if !u.IsAbs() {
		return ""
	}
	q := u.Query()
	added := false
	for _, p := range params {
		if p == "" || q.Has(p) {
			continue
		}
		q.Set(p, "1")
		added = true
	}
	if !added {
		return ""
	}
	u.RawQuery = q.Encode()
	return u.String()
}
