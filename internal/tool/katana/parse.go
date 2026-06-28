package katana

import (
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
	//
	// Schema moved between katana versions: <1.6 emits a TOP-LEVEL `forms`;
	// >=1.6 (v1.6.1 in the image) nests it under `response.forms`. We read
	// both so the fix survives katana upgrades.
	Forms    []katanaForm `json:"forms"`
	Response struct {
		Forms []katanaForm `json:"forms"`
	} `json:"response"`
}

type katanaForm struct {
	Method     string   `json:"method"`
	Action     string   `json:"action"`
	Parameters []string `json:"parameters"`
}

// parse extracts the unique set of discovered URLs from katana's JSONL
// output. Deduped + sorted for deterministic surface ordering (the
// reproducibility invariant, CLAUDE.md §10).
func parse(blob []byte) []string {
	if len(blob) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	// Split on newlines with NO per-line size cap. katana's -jsonl embeds the full response
	// BODY in each record, so a single line routinely exceeds 1 MB (real Juice Shop: 3 lines
	// up to 1.69 MB). A bufio.Scanner capped at 1 MB silently HALTS at the first oversized line
	// — truncating the discovered surface (it stopped at line 43 of 254, yielding 42 of 188
	// endpoints, and as little as 1 on a heavy SPA). bytes.Split has no cap; the blob is already
	// fully in memory, so this neither copies nor bounds line length.
	for _, raw := range bytes.Split(blob, []byte("\n")) {
		line := bytes.TrimSpace(raw)
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
		// apps gap: params live in forms, not in crawled URLs). Read both the
		// top-level (katana <1.6) and response-nested (>=1.6) form lists.
		forms := ev.Forms
		forms = append(forms, ev.Response.Forms...)
		for _, f := range forms {
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
