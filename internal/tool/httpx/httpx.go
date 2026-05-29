// Package httpx wraps the projectdiscovery/httpx HTTP prober. Used by
// ip_address (which HTTP services are live) and web_application (tech +
// header fingerprint). Its findings are recon/hygiene context (info
// severity) the L1.5 layer enriches and the security engineer triages.
// Registers via init().
package httpx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// HTTPX is the tool.Tool implementation.
type HTTPX struct{}

// New constructs an HTTPX wrapper.
func New() *HTTPX { return &HTTPX{} }

func (*HTTPX) Name() string              { return "httpx" }
func (*HTTPX) SandboxExecution() bool    { return true }
func (*HTTPX) MITRETechniques() []string { return []string{"T1595.002"} }

// Run probes a URL/host, or a whole URL list.
//
// Recognized args:
//
//	"target"  string — single URL/host (used when "targets" is absent)
//	"targets" string — newline-joined URL list → one run via -l
func (*HTTPX) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	listFile, cleanup, isList := tool.TargetList(args)
	defer cleanup()

	probeFlags := []string{"-json", "-silent", "-duc", "-title", "-tech-detect", "-web-server", "-status-code"}
	var cliArgs []string
	if isList {
		cliArgs = append([]string{"-l", listFile}, probeFlags...)
	} else {
		target, _ := args["target"].(string)
		if strings.TrimSpace(target) == "" {
			return tool.Result{}, errors.New("httpx: missing required arg 'target' or 'targets'")
		}
		cliArgs = append([]string{"-u", target}, probeFlags...)
	}
	cmd := exec.CommandContext(ctx, "httpx", cliArgs...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("httpx: exec: %w", err)
		}
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout)}, nil
}

type event struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	Tech       []string `json:"tech"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	var out []types.SandboxEmittedFinding
	sc := bufio.NewScanner(bytes.NewReader(blob))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev event
		if json.Unmarshal(line, &ev) != nil || ev.URL == "" {
			continue
		}
		raw := make([]byte, len(line))
		copy(raw, line)
		title := fmt.Sprintf("HTTP %d", ev.StatusCode)
		if ev.WebServer != "" {
			title += " — " + ev.WebServer
		}
		if len(ev.Tech) > 0 {
			title += " [" + strings.Join(ev.Tech, ", ") + "]"
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "httpx::http-service",
			Tool:            "httpx",
			Severity:        types.SeverityInfo,
			Endpoint:        ev.URL,
			Title:           title,
			Description:     ev.Title,
			RawOutput:       raw,
			MITRETechniques: []string{"T1595.002"},
			ToolArgs:        map[string]string{"status": fmt.Sprintf("%d", ev.StatusCode), "webserver": ev.WebServer},
		})
	}
	return out
}

func init() { tool.Register(New()) }
