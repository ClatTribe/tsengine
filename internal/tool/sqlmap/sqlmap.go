// Package sqlmap wraps the sqlmap SQL-injection scanner as a tsengine
// Tool. It's the web_application asset's SQLi specialist — the tool that
// fills WAVSEP's sqli category (where nuclei templates alone under-score).
// Registers via init().
//
// sqlmap is destructive-ish (it issues many injection payloads), so the
// web filter's login-protection routing skips it on auth endpoints and
// the W3 wave classifier orders it after any auth capture.
package sqlmap

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Sqlmap is the tool.Tool implementation.
type Sqlmap struct{}

// New constructs a Sqlmap wrapper.
func New() *Sqlmap { return &Sqlmap{} }

func (*Sqlmap) Name() string              { return "sqlmap" }
func (*Sqlmap) SandboxExecution() bool    { return true }
func (*Sqlmap) MITRETechniques() []string { return []string{"T1190"} }

// defaultTechnique is the fast anchor technique set: (B)oolean-blind,
// (E)rror-based, (U)nion. It deliberately OMITS (T)ime-based blind and
// (S)tacked queries — time-based *sleeps* per payload, so on a case sqlmap
// can't quickly confirm (the WAVSEP false-positive/blind cases, and any
// multi-param form) the full BEUSTQ matrix runs for minutes and blows the
// per-tool timeout, killing the dispatch with ZERO findings. Measured on
// WAVSEP: a 2-param login case takes 2m11s with all techniques vs 1.3s with
// BEU — a ~100× speedup that still flags the injection. Per-URL anchor speed
// is what lets the whole fan-out finish; the slower techniques are available
// on demand via the `technique` arg (escalation / tool-replay "dig deeper").
const defaultTechnique = "BEU"

// Run probes a single URL for SQL injection.
//
// Recognized args:
//
//	"target"    string — required, the URL (with the param to test).
//	"data"      string — optional POST body (switches sqlmap to POST).
//	"method"    string — optional HTTP method.
//	"cookie"    string — optional session cookie (authed scans).
//	"technique" string — optional sqlmap technique letters (default "BEU");
//	                     pass "BEUST"/"BEUSTQ" via escalation/replay for depth.
//	"level"     string — optional sqlmap --level (1–5).
//	"risk"      string — optional sqlmap --risk (1–3).
//
// sqlmap has no clean machine output, so we run it batch/non-interactive
// and parse its stdout injection-point report. Output: confirmed
// injections become CWE-89 findings; raw stdout is preserved.
func (*Sqlmap) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	cli, target, err := buildCLI(args)
	if err != nil {
		return tool.Result{}, err
	}
	cmd := exec.CommandContext(ctx, "sqlmap", cli...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("sqlmap: exec: %w", err)
		}
		// sqlmap exits non-zero in some no-vuln paths; parse stdout anyway.
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout, target)}, nil
}

// buildCLI assembles the sqlmap argv from the tool args (pure — no exec, so it's unit-tested). It
// returns the argv and the resolved target (for the finding-parse call).
func buildCLI(args tool.Args) ([]string, string, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return nil, "", errors.New("sqlmap: missing required arg 'target'")
	}
	technique := defaultTechnique
	if t, ok := args["technique"].(string); ok && strings.TrimSpace(t) != "" {
		technique = strings.TrimSpace(t)
	}
	cli := []string{
		"-u", target,
		"--batch",                // non-interactive (answer prompts with defaults)
		"--disable-coloring",     // clean stdout for parsing
		"--flush-session",        // reproducible — don't reuse cached results
		"--technique", technique, // fast BEU by default (see defaultTechnique)
		"--timeout", "8", // HTTP connect/read cap so a slow response can't stall
		"--retries", "1", // one retry, then move on
		"-v", "1",
	}
	// --smart heuristic-gates params (skip the non-injectable fast) — right for the anchor fan-out
	// across many URLs, but HOSTILE to deliberate extraction: on a subtle boolean oracle the basic
	// heuristic reads negative even when the param IS injectable with the right prefix/suffix/string,
	// so --smart makes sqlmap give up before the real test. When the caller is doing deliberate
	// extraction (they named the param / context / a dump target), trust them and run the full test.
	if !extractionMode(args) {
		cli = append(cli, "--smart")
	}
	if lv, ok := args["level"].(string); ok && lv != "" {
		cli = append(cli, "--level", lv)
	}
	if rk, ok := args["risk"].(string); ok && rk != "" {
		cli = append(cli, "--risk", rk)
	}
	if d, ok := args["data"].(string); ok && d != "" {
		cli = append(cli, "--data", d)
	}
	if m, ok := args["method"].(string); ok && m != "" {
		cli = append(cli, "--method", m)
	}
	if c, ok := args["cookie"].(string); ok && c != "" {
		cli = append(cli, "--cookie", c)
	}

	// Extraction / deliberate-dig args (opt-in). The anchor path never sets these — they exist
	// for the dispatch_oss / tool-replay "extract, don't just detect" caller (§9), which is the
	// whole reason to hand a blind-SQLi to sqlmap: char-by-char boolean/time EXTRACTION is
	// infeasible in the agent's request budget. Each maps to sqlmap's own flag, passed verbatim
	// (the agent supplies the injection CONTEXT — param, prefix/suffix, TRUE-string — after it
	// has observed the oracle; the wrapper just relays).
	for _, m := range []struct {
		key, flag string
	}{
		{"param", "-p"},              // the injectable parameter (skip auto-detect)
		{"prefix", "--prefix"},       // injection prefix, e.g. "'"
		{"suffix", "--suffix"},       // injection suffix, e.g. "-- -"
		{"string", "--string"},       // TRUE-response marker for a subtle boolean oracle
		{"dbms", "--dbms"},           // pin the back-end (skip fingerprinting)
		{"db", "-D"},                 // target database
		{"table", "-T"},              // target table
		{"column", "-C"},             // target column(s)
		{"file_read", "--file-read"}, // read a server file via LOAD_FILE (FILE priv)
	} {
		if v, ok := args[m.key].(string); ok && strings.TrimSpace(v) != "" {
			cli = append(cli, m.flag, v)
		}
	}
	if truthy(args["dump"]) {
		cli = append(cli, "--dump") // dump the selected db/table/column
	}
	return cli, target, nil
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec). The first row is the anchor set; the
// rest are the opt-in extraction args (dispatch_oss / tool-replay dig-deeper).
func (*Sqlmap) KnownArgs() []string {
	return []string{
		"target", "data", "method", "cookie", "technique", "level", "risk",
		"param", "prefix", "suffix", "string", "dbms", "db", "table", "column", "file_read", "dump",
	}
}

// extractionMode reports whether the caller supplied any deliberate-extraction arg — the signal
// that this is a dispatch_oss / replay "extract, don't just detect" call (not an anchor fan-out).
func extractionMode(args tool.Args) bool {
	for _, k := range []string{"param", "prefix", "suffix", "string", "db", "table", "column", "file_read"} {
		if v, ok := args[k].(string); ok && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return truthy(args["dump"])
}

// truthy reads a bool-ish arg (JSON bool true, or the strings "true"/"1"/"yes").
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "1", "yes", "y":
			return true
		}
	}
	return false
}

func init() { tool.Register(New()) }
