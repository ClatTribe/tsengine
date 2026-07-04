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
func (*FFUF) KnownArgs() []string { return []string{"target", "url", "wordlist"} }

// defaultWordlist is a small, ubiquitous list present in the sandbox image
// (seclists common.txt). Overridable via args["wordlist"].
const defaultWordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"

// Run brute-forces paths under the target. Recognized args:
//
//	"target"   string — required, the base URL (FUZZ is appended).
//	"wordlist" string — optional path (default seclists common.txt).
func (*FFUF) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target := tool.URLTarget(args) // accepts "url" as an alias for "target" (dispatch_oss agents pass url=)
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	if target == "" {
		return tool.Result{}, errors.New("ffuf: missing required arg 'target' (or 'url')")
	}
	wl := defaultWordlist
	if w, ok := args["wordlist"].(string); ok && strings.TrimSpace(w) != "" {
		wl = w
	}
	f, err := os.CreateTemp("", "ffuf-*.json")
	if err != nil {
		return tool.Result{}, err
	}
	out := f.Name()
	_ = f.Close()
	defer os.Remove(out)

	// gosec G204: binary is literal "ffuf"; target is a validated tool.Args
	// asset target, wl is a path baked into the sandbox image.
	cmd := exec.CommandContext(ctx, "ffuf", //nolint:gosec
		"-u", target+"/FUZZ", "-w", wl,
		"-mc", "200,204,301,302,307,401,403,405",
		"-of", "json", "-o", out, "-s")
	combined, runErr := cmd.CombinedOutput()
	blob, rerr := os.ReadFile(out) //nolint:gosec // temp file we created
	if rerr != nil || len(blob) == 0 {
		return tool.Result{Output: string(combined)}, nil
	}
	_ = runErr
	findings, surface := parse(blob)
	return tool.Result{Output: string(blob), Findings: findings, DiscoveredURLs: surface}, nil
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
