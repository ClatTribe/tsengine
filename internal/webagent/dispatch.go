package webagent

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// dispatch.go is the §13 "wrap OSS, don't rebuild" seam for the webagent. Some vuln classes are the job
// of a specialized OSS tool, NOT of LLM reasoning + the in-scope request budget: automated blind-SQLi
// EXTRACTION (sqlmap), WordPress CVEs (wpscan/nuclei), password brute-force (hydra), content fuzzing at
// scale (ffuf). Reimplementing those in-house would violate §13 and blow the budget. So instead of N
// in-house tools, the agent gets ONE registry gateway — dispatch_oss(tool, args) — that hands off to the
// sandbox tool-server, mirroring the L2 Lead's dispatch_l2_probe (CLAUDE.md §2.6/§9: one slot reaches the
// whole registry tier, so the LLM catalog stays small).
//
// The host-side webagent has no sandbox of its own, so the run wires a Dispatcher (nil = not available:
// the tool degrades gracefully and says so, never pretends). The live sandbox-backed Dispatcher is the
// honestly-gated half (needs the sandbox image + a spawned tool-server), wired by the platform/tsbench
// path; standalone `web-investigate --target` leaves it nil.

// Dispatcher runs one OSS specialist out-of-band and returns its textual result. Injected by the caller.
type Dispatcher interface {
	RunTool(ctx context.Context, tool string, args map[string]any) (string, error)
}

// ossSpecialists is the curated registry the agent may dispatch to, each with WHEN to reach for it. These
// are OSS specialists the L1 pipeline already wraps — the webagent just gains on-demand access to them.
var ossSpecialists = map[string]string{
	"sqlmap":    "automated SQL-injection EXTRACTION — boolean/time-based BLIND, error-based, UNION; dump tables/columns when manual extraction is infeasible (the blind-SQLi answer)",
	"wpscan":    "WordPress core/plugin/theme CVE detection + user enumeration (the WordPress-CVE answer)",
	"nuclei":    "known-CVE / misconfiguration template scan against a URL",
	"ffuf":      "fuzzing at scale. Put the FUZZ keyword ANYWHERE in url (e.g. url=\"http://t/order/FUZZ/receipt\") for path-segment/IDOR fuzzing; for an OBJECT-ID sweep add range=\"lo-hi\" ({\"url\":\"http://t/order/FUZZ/receipt\",\"range\":\"300000-300999\"}) to generate a numeric wordlist + auto-calibrate away the uniform not-found so only real objects show; add match=\"<regex>\" (e.g. \"flag\") to keep only matching responses. No FUZZ + no range = dir-brute the seclists wordlist under url",
	"hydra":     "credential brute-force against a discovered NETWORK login (bigger than try_default_creds' short list). REQUIRES args {\"target\":\"<host>\",\"service\":\"<ssh|ftp|mysql|postgres|redis|smb|rdp|telnet|vnc>\"} (+ optional {\"port\":<n>}); it errors without `service` — hydra can't guess which protocol to brute",
	"padbuster": "AES-CBC / block-cipher PADDING-ORACLE attack — decrypt a ciphertext byte-by-byte, or FORGE (encrypt) an arbitrary plaintext into a valid cookie/token (the crypto answer; char-by-char work the request budget can't do)",
}

// dispatchOSSHelp builds the dispatch_oss tool help from ossSpecialists — the single source of truth —
// so EVERY specialist (and its arg requirements) reaches the LLM. The help used to be a hand-maintained
// summary that drifted from the registry: it omitted padbuster entirely (so the crypto specialist was
// invisible) and never told the agent hydra REQUIRES a `service` arg (so dispatch_oss(hydra,{target})
// silently dead-ended — the #809 missing-required-arg-guidance class). Generating it here keeps the two
// in lockstep.
func dispatchOSSHelp() string {
	names := make([]string, 0, len(ossSpecialists))
	for n := range ossSpecialists {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("dispatch_oss(tool, args) — hand a SPECIALIZED job to an OSS specialist instead of doing it by hand. `args` is that tool's own argument object (most take {\"url\":\"...\"} or {\"target\":\"...\"}, e.g. sqlmap: {\"url\":\"...\",\"data\":\"...\"}). Use this — don't reimplement char-by-char blind extraction or a CVE exploit yourself. Specialists:")
	for _, n := range names {
		b.WriteString("\n  • " + n + " — " + ossSpecialists[n])
	}
	return b.String()
}

func ossToolList() string {
	names := make([]string, 0, len(ossSpecialists))
	for n := range ossSpecialists {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// tDispatchOSS hands a specialized job to an OSS tool via the injected Dispatcher.
func tDispatchOSS(cc *Context, args map[string]any) string {
	tool := strings.ToLower(strings.TrimSpace(argStr(args, "tool")))
	if tool == "" {
		return "ERROR: tool is required. OSS specialists: " + ossToolList()
	}
	if _, ok := ossSpecialists[tool]; !ok {
		return fmt.Sprintf("unknown OSS tool %q. Available: %s", tool, ossToolList())
	}
	if cc.dispatcher == nil {
		return fmt.Sprintf("OSS-tool dispatch unavailable in this run — %s runs in the sandbox tool-server, which this host-side session isn't wired to. (The platform/tsbench path provides it.) Continue with the in-agent tools, or hand this class to the L1 scan.", tool)
	}
	targs, _ := args["args"].(map[string]any) // tool-specific args (e.g. sqlmap: {url, data, technique})
	out, err := cc.dispatcher.RunTool(cc.ctx, tool, targs)
	if err != nil {
		return "OSS dispatch (" + tool + ") failed: " + err.Error()
	}
	cc.turnN++
	// head+tail, not head-only: an OSS dump (sqlmap tables, hydra creds, ffuf hits) puts the EXTRACTED
	// artifact near the END, so pure head-truncation dropped the very data the agent dispatched for and
	// left the signed evidence bundle without the proof (the #807 fix, previously applied to
	// send_request but not here).
	ev := headTail(out, evidenceBodyCap-evidenceBodyTail, evidenceBodyTail)
	cc.History = append(cc.History, Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: "dispatch:" + tool,
		URL: strOr(targs["url"], strOr(targs["target"], "")), Status: 200, Elapsed: "0s", RespSnippet: ev,
	})
	snip := headTail(out, llmSnippetCap-llmSnippetTail, llmSnippetTail)
	return fmt.Sprintf("t-%03d  %s result:\n%s", cc.turnN, tool, snip)
}
