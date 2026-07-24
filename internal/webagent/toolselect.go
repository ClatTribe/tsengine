package webagent

import (
	"os"
	"strings"
	"sync"

	"github.com/ClatTribe/tsengine/internal/toolselect"
)

// Dynamic tool selection (ADR 0016). The offensive agent has 23 tools; presenting all of them every
// turn is ~2x the L2-CAP (<=12), where tool-use accuracy degrades. selectedTools shrinks the prompt's
// TOOLS: section to the always-on CORE + the specialists most relevant to the CURRENT subgoal (derived
// from the recent transcript + L1 seeds), capped at maxActiveTools.
//
// SAFE BY CONSTRUCTION: this only shapes what the prompt SHOWS. The handler registry in Investigate is
// built from the full tools(), so a hidden tool is still fully callable — if the model names one that
// wasn't surfaced this turn, it still runs (and the "unknown tool" path lists every name for discovery).
// So selection can only focus attention, never remove a capability. ON BY DEFAULT (the best-practice:
// keep the visible catalog within the L2-CAP); set TSENGINE_TOOL_SELECT=0 to disable and render the
// full 23-tool catalog (an operator kill-switch for debugging / A-B).

const maxActiveTools = 12

// coreTools are always visible — the tools needed in almost any turn regardless of subgoal.
var coreTools = map[string]bool{
	"send_request":    true,
	"record_finding":  true,
	"confirm_exploit": true,
	"dispatch_oss":    true,
	"list_routes":     true,
	"finish":          true,
}

// toolTags maps each specialist to curated relevance hints (the CORE tools don't need them — they're
// always on). A tool absent here with no tags still ranks on its help text, just more weakly.
var toolTags = map[string][]string{
	"discover_content":   {"recon", "content", "discovery", "hidden", "params"},
	"graphql_introspect": {"graphql", "schema", "api", "introspection"},
	"browser_render":     {"xss", "dom", "browser", "javascript"},
	"sqli_bool_probe":    {"sqli", "sql", "injection", "blind", "boolean"},
	"nosqli_probe":       {"nosqli", "mongodb", "injection", "operator"},
	"bola_probe":         {"bola", "idor", "authz", "authorization", "object"},
	"privesc_probe":      {"privesc", "privilege", "escalation", "mass", "assignment", "bfla"},
	"session_idor_probe": {"idor", "session", "login", "authz"},
	"tamper_probe":       {"tamper", "parameter", "access", "control", "authz", "header", "idor", "privilege"},
	"race_probe":         {"race", "toctou", "limit", "concurrency"},
	"jwt_crack":          {"jwt", "token", "hmac", "forge", "session"},
	"crack_hash":         {"hash", "creds", "password", "md5", "sha1"},
	"try_default_creds":  {"creds", "default", "login", "brute"},
	"oob_url":            {"oob", "blind", "ssrf", "callback", "interactsh"},
	"oob_check":          {"oob", "blind", "ssrf", "callback"},
	"ssh_exec":           {"ssh", "creds", "lateral", "movement", "exec"},
	"note_defense":       {"waf", "filter", "defense"},
}

var (
	webCatalogOnce sync.Once
	webCatalog     *toolselect.Catalog
)

func toolCatalog() *toolselect.Catalog {
	webCatalogOnce.Do(func() {
		var ts []toolselect.Tool
		for _, t := range tools() {
			ts = append(ts, toolselect.Tool{
				Name:        t.name,
				Description: t.help, // the rich help string is the searchable corpus
				Tags:        toolTags[t.name],
				AlwaysOn:    coreTools[t.name],
			})
		}
		webCatalog = toolselect.NewCatalog(ts)
	})
	return webCatalog
}

// toolSelectEnabled reports whether dynamic selection is on. Default ON; disabled only by an explicit
// TSENGINE_TOOL_SELECT=0 (the kill-switch), so the best-practice small catalog is the standard path.
func toolSelectEnabled() bool { return os.Getenv("TSENGINE_TOOL_SELECT") != "0" }

// selectedTools returns the toolDefs to render in the prompt this turn. Default (flag off) → the full
// catalog, unchanged. Flag on → CORE + the specialists most relevant to the current subgoal.
func selectedTools(cc *Context, transcript []string) []toolDef {
	all := tools()
	if !toolSelectEnabled() {
		return all
	}
	sel := toolCatalog().Select(toolselect.Query{Task: currentSubgoal(cc, transcript), MaxActive: maxActiveTools})
	active := make(map[string]bool, len(sel.Tools))
	for _, t := range sel.Tools {
		active[t.Name] = true
	}
	out := make([]toolDef, 0, len(active))
	for _, t := range all { // preserve the stable tools() order
		if active[t.name] {
			out = append(out, t)
		}
	}
	return out
}

// currentSubgoal builds the retrieval query from the agent's live context: the L1 seed findings (what
// we're here to confirm) + the tail of the transcript (its most recent reasoning/actions). On turn 0
// (empty transcript) it leans on the seeds, else a recon default.
func currentSubgoal(cc *Context, transcript []string) string {
	var b strings.Builder
	for _, s := range cc.Seeds {
		// Class is the strongest selection signal (sqli → sqli_bool_probe, xss → browser_render, …);
		// Route adds surface context.
		b.WriteString(s.Class)
		b.WriteByte(' ')
		b.WriteString(s.Route)
		b.WriteByte(' ')
	}
	// The last few transcript entries carry the current line of attack.
	tail := transcript
	if len(tail) > 3 {
		tail = tail[len(tail)-3:]
	}
	for _, e := range tail {
		b.WriteString(e)
		b.WriteByte(' ')
	}
	q := strings.TrimSpace(b.String())
	if q == "" {
		return "recon discover the attack surface routes and hidden content"
	}
	if len(q) > 2000 { // bound the query; recent context dominates relevance
		q = q[len(q)-2000:]
	}
	return q
}
