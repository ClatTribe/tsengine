// Package kiterunner wraps assetnote/kiterunner as a tsengine depth Tool
// for the api asset. It fills a gap openapi_spec_ingest can't: the spec
// only lists DOCUMENTED endpoints; kiterunner brute-forces UNDOCUMENTED /
// shadow API routes (old versions, debug handlers, internal endpoints)
// from an API-route wordlist. Fired by the escalation engine after a spec
// is ingested. Registers via init().
package kiterunner

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Kiterunner is the tool.Tool implementation.
type Kiterunner struct{}

// New constructs a Kiterunner wrapper.
func New() *Kiterunner { return &Kiterunner{} }

func (*Kiterunner) Name() string              { return "kiterunner" }
func (*Kiterunner) SandboxExecution() bool    { return true }
func (*Kiterunner) MITRETechniques() []string { return []string{"T1595.003"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Kiterunner) KnownArgs() []string { return []string{"target", "wordlist"} }

// defaultWordlist is the API-route list baked into the sandbox image.
const defaultWordlist = "/usr/share/kiterunner/routes-small.kite"

// Run brute-forces API routes under the target. Recognized args:
//
//	"target"   string — required, the API base URL.
//	"wordlist" string — optional .kite/.txt route list.
func (*Kiterunner) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	target = strings.TrimSpace(target)
	if target == "" {
		return tool.Result{}, errors.New("kiterunner: missing required arg 'target'")
	}
	wl := defaultWordlist
	if w, ok := args["wordlist"].(string); ok && strings.TrimSpace(w) != "" {
		wl = w
	}
	cmd := exec.CommandContext(ctx, "kr", "scan", target, "-w", wl, "-q", "--fail-status-codes", "400,404,403,500,501,502,503")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "kiterunner: " + err.Error()}, nil
		}
	}
	findings, surface := parse(out)
	return tool.Result{Output: string(out), Findings: findings, DiscoveredURLs: surface}, nil
}

// krHit matches a kiterunner result line:
//
//	GET    200 [    1234,   56,   7] https://host/api/v1/admin   0cf6841b...
var krHit = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\d{3})\s+\[[^\]]*\]\s+(\S+)`)

func parse(out []byte) ([]types.SandboxEmittedFinding, []string) {
	var findings []types.SandboxEmittedFinding
	var surface []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(out), "\n") {
		m := krHit.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		method, status, url := m[1], m[2], m[3]
		key := method + " " + url
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		findings = append(findings, types.SandboxEmittedFinding{
			RuleID:          "kiterunner::undocumented-route",
			Tool:            "kiterunner",
			Severity:        types.SeverityInfo,
			Endpoint:        url,
			Title:           fmt.Sprintf("Undocumented API route (%s %s): %s", method, status, url),
			MITRETechniques: []string{"T1595.003"},
			ToolArgs:        map[string]string{"method": method, "status": status},
		})
		surface = append(surface, method+" "+url)
	}
	return findings, surface
}

func init() { tool.Register(New()) }
