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
	findings, surface := parse(stdout)
	// DiscoveredURLs is the recon channel: the open host:port endpoints
	// become the ip_address scan surface that PlanFanout routes per-port
	// (nuclei tag routing, deep nmap). Open ports are ALSO emitted as
	// findings (above) for the dashboard — recon and detection both keep
	// their copy (CLAUDE.md §5.1).
	return tool.Result{Output: string(stdout), Findings: findings, DiscoveredURLs: surface}, nil
}

type event struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// parse returns the open-port findings AND the host:port surface for the
// recon channel (deduped, deterministic order).
func parse(blob []byte) ([]types.SandboxEmittedFinding, []string) {
	if len(blob) == 0 {
		return nil, nil
	}
	var out []types.SandboxEmittedFinding
	var surface []string
	seen := map[string]struct{}{}
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
		endpoint := fmt.Sprintf("%s:%d", host, ev.Port)
		raw := make([]byte, len(line))
		copy(raw, line)
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "naabu::open-port",
			Tool:            "naabu",
			Severity:        types.SeverityInfo,
			Endpoint:        endpoint,
			Title:           fmt.Sprintf("Open port %d on %s", ev.Port, host),
			RawOutput:       raw,
			MITRETechniques: []string{"T1046"},
			ToolArgs:        map[string]string{"port": fmt.Sprintf("%d", ev.Port)},
		})
		if _, dup := seen[endpoint]; !dup {
			seen[endpoint] = struct{}{}
			surface = append(surface, endpoint)
		}
	}
	return out, surface
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Naabu) KnownArgs() []string { return []string{"target", "ports"} }

func init() { tool.Register(New()) }
