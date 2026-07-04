package tool

import (
	"os"
	"strings"
)

// TargetList reads the optional "targets" arg — a newline-joined URL
// list produced by the recon→fan-out planner — and, if present, writes
// it to a temp file for tools that accept a -list/-l input file (nuclei,
// httpx). Returns the file path + a cleanup func, or ("", noop, false)
// when no list was supplied (single-target path).
//
// Running one nuclei/httpx invocation over a URL list is far cheaper
// than one invocation per URL — it's what keeps the web fan-out from
// degenerating into N full template runs.
func TargetList(args Args) (path string, cleanup func(), ok bool) {
	raw, _ := args["targets"].(string)
	lines := nonEmptyLines(raw)
	if len(lines) == 0 {
		return "", func() {}, false
	}
	f, err := os.CreateTemp("", "tsengine-targets-*.txt")
	if err != nil {
		return "", func() {}, false
	}
	_, _ = f.WriteString(strings.Join(lines, "\n") + "\n")
	_ = f.Close()
	return f.Name(), func() { _ = os.Remove(f.Name()) }, true
}

// URLTarget resolves a single-URL target arg, accepting "url" as an alias for "target". The
// dispatch_oss tool description's only worked example passes {"url":"..."} (sqlmap), and an LLM
// naturally uses "url" for an HTTP endpoint — so without the alias a dispatch_oss(wpscan|nuclei|
// ffuf|padbuster, {url:...}) call died with "missing required arg 'target'" and the whole probe
// silently dead-ended (the exact class sqlmap's own url-alias fixed). "target" wins when both are
// set; whitespace-only counts as absent. Returns "" when neither is present.
func URLTarget(args Args) string {
	if t, _ := args["target"].(string); strings.TrimSpace(t) != "" {
		return t
	}
	t, _ := args["url"].(string)
	return t
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}
