// Package dnstwist wraps dnstwist (domain permutation / typosquat engine)
// as a tsengine Tool for the domain asset. It fills a gap the enumerators
// can't: subfinder/amass/crt.sh find YOUR subdomains; dnstwist finds
// LOOK-ALIKE domains an attacker registered to phish your users
// (typos, homoglyphs, TLD swaps). Registers via init().
package dnstwist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// DNSTwist is the tool.Tool implementation.
type DNSTwist struct{}

// New constructs a DNSTwist wrapper.
func New() *DNSTwist { return &DNSTwist{} }

func (*DNSTwist) Name() string              { return "dnstwist" }
func (*DNSTwist) SandboxExecution() bool    { return true }
func (*DNSTwist) MITRETechniques() []string { return []string{"T1583.001", "T1566"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*DNSTwist) KnownArgs() []string { return []string{"target"} }

// Run generates + resolves domain permutations. Recognized args:
//
//	"target" string — required, the apex domain.
//
// --registered keeps only permutations that actually resolve (live
// look-alikes worth flagging), not the full permutation space.
func (*DNSTwist) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return tool.Result{}, errors.New("dnstwist: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "dnstwist", "--format", "json", "--registered", target)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("dnstwist: exec: %w", err)
		}
	}
	return tool.Result{Output: string(out), Findings: parse(out, target)}, nil
}

type perm struct {
	Fuzzer string   `json:"fuzzer"`
	Domain string   `json:"domain"`
	DNSA   []string `json:"dns_a"`
	DNSMX  []string `json:"dns_mx"`
}

func parse(blob []byte, apex string) []types.SandboxEmittedFinding {
	var perms []perm
	if json.Unmarshal(blob, &perms) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, p := range perms {
		dom := strings.ToLower(strings.TrimSpace(p.Domain))
		if dom == "" || dom == apex {
			continue // the original, or the "*original" marker row
		}
		if len(p.DNSA) == 0 {
			continue // not actually registered/resolving
		}
		// A registered look-alike with MX records is higher-risk (can
		// receive mail → credential phishing).
		sev := types.SeverityLow
		if len(p.DNSMX) > 0 {
			sev = types.SeverityMedium
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "dnstwist::lookalike-domain",
			Tool:            "dnstwist",
			Severity:        sev,
			Endpoint:        dom,
			Title:           "Registered look-alike domain: " + dom,
			Description:     fmt.Sprintf("Permutation (%s) of %s resolves to %v — potential phishing/impersonation.", p.Fuzzer, apex, p.DNSA),
			MITRETechniques: []string{"T1583.001"},
			ToolArgs:        map[string]string{"fuzzer": p.Fuzzer, "has_mx": fmt.Sprintf("%t", len(p.DNSMX) > 0)},
		})
	}
	return out
}

func init() { tool.Register(New()) }
