// Package ffuf wraps the ffuf web fuzzer as a tsengine depth Tool for the
// web_application asset. It fills a gap katana can't: katana only follows
// links that exist in the response; ffuf BRUTE-FORCES hidden paths (admin
// panels, backups, .git, API roots) from a wordlist. Fired by the
// escalation engine when the crawl surface is thin — content discovery is
// expensive, so it runs targeted, not on every scan. Registers via init().
package ffuf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// FFUF is the tool.Tool implementation.
type FFUF struct{}

// New constructs an FFUF wrapper.
func New() *FFUF { return &FFUF{} }

func (*FFUF) Name() string              { return "ffuf" }
func (*FFUF) SandboxExecution() bool    { return true }
func (*FFUF) MITRETechniques() []string { return []string{"T1083", "T1595.003"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*FFUF) KnownArgs() []string {
	return []string{"target", "url", "wordlist", "range", "match", "cookie", "calibrate"}
}

// defaultWordlist is a small, ubiquitous list present in the sandbox image
// (seclists common.txt). Overridable via args["wordlist"].
const defaultWordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"

// maxRange caps a generated numeric wordlist so a huge/typo'd range can't turn one dispatch into an
// unbounded scan (the cost twin of the fan-out cap).
const maxRange = 100000

// fuzzURL places the FUZZ keyword. Faithful to real ffuf: if the caller already put FUZZ IN the url
// (e.g. .../order/FUZZ/receipt — the IDOR/enumeration case), use it verbatim; otherwise append /FUZZ
// (the dir-brute default). The old wrapper always appended /FUZZ, so FUZZ-in-the-middle was impossible.
func fuzzURL(target string) string {
	if strings.Contains(target, "FUZZ") {
		return target
	}
	return strings.TrimRight(strings.TrimSpace(target), "/") + "/FUZZ"
}

// numericWordlist writes a temp wordlist of the integers in spec ("lo-hi", e.g. "300000-300999") — the
// IDOR object-id sweep that a word wordlist can't do. Bounded by maxRange. Returns the file path + a
// cleanup func. This is what lets ffuf enumerate /order/FUZZ/receipt over an id range.
func numericWordlist(spec string) (string, func(), error) {
	lo, hi, err := parseRange(spec)
	if err != nil {
		return "", func() {}, err
	}
	f, err := os.CreateTemp("", "ffuf-nums-*.txt")
	if err != nil {
		return "", func() {}, err
	}
	var sb strings.Builder
	for i := lo; i <= hi; i++ {
		fmt.Fprintf(&sb, "%d\n", i)
	}
	if _, err := f.WriteString(sb.String()); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", func() {}, err
	}
	_ = f.Close()
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

func parseRange(spec string) (lo, hi int, err error) {
	parts := strings.SplitN(strings.TrimSpace(spec), "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("ffuf: range %q must be lo-hi (e.g. 300000-300999)", spec)
	}
	if lo, err = strconv.Atoi(strings.TrimSpace(parts[0])); err != nil {
		return 0, 0, fmt.Errorf("ffuf: bad range low: %w", err)
	}
	if hi, err = strconv.Atoi(strings.TrimSpace(parts[1])); err != nil {
		return 0, 0, fmt.Errorf("ffuf: bad range high: %w", err)
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("ffuf: range hi<lo (%d<%d)", hi, lo)
	}
	if hi-lo+1 > maxRange {
		hi = lo + maxRange - 1 // bound the sweep
	}
	return lo, hi, nil
}

// Run fuzzes the target. Recognized args:
//
//	"target"/"url" string — required. If it contains FUZZ, used verbatim; else /FUZZ is appended.
//	"wordlist"     string — optional path (default seclists common.txt).
//	"range"        string — optional "lo-hi"; generates a NUMERIC wordlist (IDOR/id enumeration) +
//	                        auto-calibration so the uniform not-found response is filtered out.
//	"match"        string — optional regex; ONLY responses whose body matches are reported (ffuf
//	                        -mr, required via -mmode and, not OR'd against the status matcher).
//	"cookie"       string — optional "name=v; name2=v2"; sent as a Cookie header so an AUTHENTICATED
//	                        surface (IDOR/SQLi behind login) is reachable. Injected by dispatch_oss from
//	                        the agent's session; redacted from the returned output.
func (*FFUF) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target := tool.URLTarget(args) // accepts "url" as an alias for "target" (dispatch_oss agents pass url=)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("ffuf: missing required arg 'target' (or 'url')")
	}
	u := fuzzURL(target)
	wl := defaultWordlist
	// -ac (auto-calibration) is OPT-IN, never forced. It can over-filter to ZERO results — and when a
	// `match` regex is set the regex IS the filter, so -ac is redundant. Forcing it on every range (the
	// original #833 behavior) zeroed a real authenticated IDOR sweep with no override (grounded live).
	autocalib, _ := args["calibrate"].(bool)
	if rng, ok := args["range"].(string); ok && strings.TrimSpace(rng) != "" {
		wf, cleanup, err := numericWordlist(rng)
		if err != nil {
			return tool.Result{}, err
		}
		defer cleanup()
		wl = wf
	} else if w, ok := args["wordlist"].(string); ok && strings.TrimSpace(w) != "" {
		wl = w
	}
	f, err := os.CreateTemp("", "ffuf-*.json")
	if err != nil {
		return tool.Result{}, err
	}
	out := f.Name()
	_ = f.Close()
	defer os.Remove(out)

	matchRe := ""
	if m, ok := args["match"].(string); ok {
		matchRe = strings.TrimSpace(m)
	}
	// When matching on body content, -mr must be the DECIDING matcher: set -mc all + -mmode and so a hit
	// requires the regex (else ffuf ORs -mr with the default status matcher and every 2xx/3xx shows,
	// defeating the match). Without a match, keep the status-code matcher.
	mc := "200,204,301,302,307,401,403,405"
	if matchRe != "" {
		mc = "all"
	}
	// gosec G204: binary is literal "ffuf"; u/wl are validated tool.Args (asset target / a path).
	cmdArgs := []string{
		"-u", u, "-w", wl,
		"-mc", mc,
		"-of", "json", "-o", out, "-s",
	}
	cookie := ""
	if c, ok := args["cookie"].(string); ok {
		cookie = strings.TrimSpace(c)
	}
	if cookie != "" {
		cmdArgs = append(cmdArgs, "-H", "Cookie: "+cookie)
	}
	if autocalib {
		cmdArgs = append(cmdArgs, "-ac")
	}
	if matchRe != "" {
		cmdArgs = append(cmdArgs, "-mr", matchRe, "-mmode", "and")
	}
	cmd := exec.CommandContext(ctx, "ffuf", cmdArgs...) //nolint:gosec
	combined, runErr := cmd.CombinedOutput()
	blob, rerr := os.ReadFile(out) //nolint:gosec // temp file we created
	if rerr != nil || len(blob) == 0 {
		return tool.Result{Output: redactCookie(string(combined), cookie)}, nil
	}
	_ = runErr
	findings, surface := parse(blob)
	return tool.Result{Output: redactCookie(string(blob), cookie), Findings: findings, DiscoveredURLs: surface}, nil
}

// redactCookie strips the injected session cookie value from ffuf's output (it echoes the -H Cookie
// header in its config), so the agent's session never lands in the transcript / signed evidence.
func redactCookie(out, cookie string) string {
	if cookie == "" {
		return out
	}
	return strings.ReplaceAll(out, cookie, "<redacted-session>")
}

type report struct {
	Results []struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
		Length int    `json:"length"`
	} `json:"results"`
}

func parse(blob []byte) ([]types.SandboxEmittedFinding, []string) {
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil, nil
	}
	var findings []types.SandboxEmittedFinding
	var surface []string
	for _, res := range r.Results {
		findings = append(findings, types.SandboxEmittedFinding{
			RuleID:          "ffuf::content-discovered",
			Tool:            "ffuf",
			Severity:        types.SeverityInfo,
			Endpoint:        res.URL,
			Title:           fmt.Sprintf("Hidden path discovered (%d): %s", res.Status, res.URL),
			MITRETechniques: []string{"T1083"},
			ToolArgs:        map[string]string{"status": fmt.Sprintf("%d", res.Status)},
		})
		surface = append(surface, res.URL)
	}
	return findings, surface
}

func init() { tool.Register(New()) }
