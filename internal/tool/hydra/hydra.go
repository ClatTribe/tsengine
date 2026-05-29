// Package hydra wraps THC-Hydra (network login brute-forcer) as a tsengine
// depth Tool. It fills a gap no current tool covers: testing services for
// DEFAULT / weak credentials (SSH, FTP, MySQL, Postgres, Redis, …). Fired
// by the escalation engine on a discovered auth service (ip) — credential
// brute is intrusive + slow, so it runs targeted, with a small built-in
// default-creds list (not a full dictionary attack). Registers via init().
package hydra

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Hydra is the tool.Tool implementation.
type Hydra struct{}

// New constructs a Hydra wrapper.
func New() *Hydra { return &Hydra{} }

func (*Hydra) Name() string              { return "hydra" }
func (*Hydra) SandboxExecution() bool    { return true }
func (*Hydra) MITRETechniques() []string { return []string{"T1110.001", "T1078.001"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Hydra) KnownArgs() []string { return []string{"target", "service", "port"} }

// supportedServices are the modules we allow (read-ish auth checks).
var supportedServices = map[string]bool{
	"ssh": true, "ftp": true, "mysql": true, "postgres": true,
	"redis": true, "smb": true, "rdp": true, "telnet": true, "vnc": true,
}

// defaultCombos is the small default/weak credential set. Deliberately
// tiny — this is a default-creds CHECK, not a dictionary attack.
const defaultCombos = `root:root
root:toor
root:
admin:admin
admin:password
admin:
user:user
test:test
postgres:postgres
mysql:mysql
oracle:oracle
guest:guest`

// Run brute-checks a service for default creds. Recognized args:
//
//	"target"  string — required, host/IP.
//	"service" string — required, one of supportedServices.
//	"port"    int|string — optional, non-default port.
func (*Hydra) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	host, _ := args["target"].(string)
	host = strings.TrimSpace(host)
	if host == "" {
		return tool.Result{}, errors.New("hydra: missing required arg 'target'")
	}
	service, _ := args["service"].(string)
	service = strings.ToLower(strings.TrimSpace(service))
	if !supportedServices[service] {
		return tool.Result{}, fmt.Errorf("hydra: unsupported/empty service %q", service)
	}

	f, err := os.CreateTemp("", "hydra-combo-*.txt")
	if err != nil {
		return tool.Result{}, err
	}
	combo := f.Name()
	_, _ = f.WriteString(defaultCombos)
	_ = f.Close()
	defer os.Remove(combo)

	cli := []string{"-C", combo, "-t", "4", "-f"}
	if p, ok := portArg(args["port"]); ok {
		cli = append(cli, "-s", p)
	}
	cli = append(cli, host, service)

	cmd := exec.CommandContext(ctx, "hydra", cli...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "hydra: " + err.Error()}, nil
		}
	}
	return tool.Result{Output: string(out), Findings: parse(out, host, service)}, nil
}

func portArg(v any) (string, bool) {
	switch p := v.(type) {
	case int:
		if p > 0 {
			return fmt.Sprintf("%d", p), true
		}
	case string:
		if strings.TrimSpace(p) != "" {
			return p, true
		}
	}
	return "", false
}

// hydraHit matches hydra's success line:
//
//	[22][ssh] host: 10.0.0.5   login: root   password: toor
var hydraHit = regexp.MustCompile(`login:\s*(\S+)\s+password:\s*(\S*)`)

func parse(out []byte, host, service string) []types.SandboxEmittedFinding {
	var findings []types.SandboxEmittedFinding
	for _, m := range hydraHit.FindAllStringSubmatch(string(out), -1) {
		login, pass := m[1], m[2]
		findings = append(findings, types.SandboxEmittedFinding{
			RuleID:          "hydra::default-credentials",
			Tool:            "hydra",
			Severity:        types.SeverityCritical,
			Endpoint:        fmt.Sprintf("%s (%s)", host, service),
			Title:           fmt.Sprintf("Default/weak credentials on %s: %s:%s", service, login, pass),
			Description:     "Service accepts a default/weak credential pair — immediate unauthorized access.",
			MITRETechniques: []string{"T1110.001"},
			ToolArgs:        map[string]string{"service": service, "login": login},
		})
	}
	return findings
}

func init() { tool.Register(New()) }
