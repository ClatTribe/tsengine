// Package naabu wraps the projectdiscovery/naabu fast port scanner.
// Used by the ip_address asset alongside nmap (naabu is faster for
// discovery; nmap does service/version detection). Registers via init().
//
// The sandbox runs --cap-drop=ALL, so naabu must use CONNECT scan
// (-s c) rather than the default SYN scan, which needs CAP_NET_RAW.
package naabu

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

// Naabu is the tool.Tool implementation.
type Naabu struct{}

// New constructs a Naabu wrapper.
func New() *Naabu { return &Naabu{} }

func (*Naabu) Name() string              { return "naabu" }
func (*Naabu) SandboxExecution() bool    { return true }
func (*Naabu) MITRETechniques() []string { return []string{"T1046"} }

// Run scans a host for open ports.
//
// Recognized args:
//
//	"target" string — required, host/IP/CIDR.
//	"ports"  string — optional -p value (default: naabu top-100).
func (*Naabu) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("naabu: missing required arg 'target'")
	}
	cli := []string{"-host", target, "-s", "c", "-json", "-silent", "-duc"}
	if p, ok := args["ports"].(string); ok && p != "" {
		cli = append(cli, "-p", p)
	}
	cmd := exec.CommandContext(ctx, "naabu", cli...)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("naabu: exec: %w", err)
		}
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout)}, nil
}

type event struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	var out []types.SandboxEmittedFinding
	sc := bufio.NewScanner(bytes.NewReader(blob))
	sc.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev event
		if json.Unmarshal(line, &ev) != nil || ev.Port == 0 {
			continue
		}
		host := ev.IP
		if host == "" {
			host = ev.Host
		}
		raw := make([]byte, len(line))
		copy(raw, line)
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "naabu::open-port",
			Tool:            "naabu",
			Severity:        types.SeverityInfo,
			Endpoint:        fmt.Sprintf("%s:%d", host, ev.Port),
			Title:           fmt.Sprintf("Open port %d on %s", ev.Port, host),
			RawOutput:       raw,
			MITRETechniques: []string{"T1046"},
			ToolArgs:        map[string]string{"port": fmt.Sprintf("%d", ev.Port)},
		})
	}
	return out
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Naabu) KnownArgs() []string { return []string{"target", "ports"} }

func init() { tool.Register(New()) }
