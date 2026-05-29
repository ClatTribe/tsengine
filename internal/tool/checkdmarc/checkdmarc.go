// Package checkdmarc wraps the `checkdmarc` DNS-hygiene tool (SPF / DMARC
// / MX / DNSSEC validation) as a tsengine Tool for the domain asset.
// Replaces hand-rolled dnspython SPF/DMARC heuristics with a maintained
// OSS validator (strix migrated the same way — L1-optimization.md §3.4).
// Registers via init().
package checkdmarc

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

// CheckDMARC is the tool.Tool implementation.
type CheckDMARC struct{}

// New constructs a CheckDMARC wrapper.
func New() *CheckDMARC { return &CheckDMARC{} }

func (*CheckDMARC) Name() string              { return "checkdmarc" }
func (*CheckDMARC) SandboxExecution() bool    { return true }
func (*CheckDMARC) MITRETechniques() []string { return []string{"T1566"} } // phishing surface

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*CheckDMARC) KnownArgs() []string { return []string{"target"} }

// report mirrors the subset of checkdmarc's JSON we act on.
type report struct {
	Domain string `json:"domain"`
	SPF    struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	} `json:"spf"`
	DMARC struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
		Tags  struct {
			P struct {
				Value string `json:"value"`
			} `json:"p"`
		} `json:"tags"`
	} `json:"dmarc"`
}

// Run validates a domain's email-auth posture. Recognized args:
//
//	"target" string — required, the apex domain.
//
// Emits a finding per weak control: no/invalid SPF, no/invalid DMARC, or a
// permissive DMARC policy (p=none — monitors but doesn't block spoofing).
func (*CheckDMARC) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return tool.Result{}, errors.New("checkdmarc: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "checkdmarc", "--format", "json", target)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("checkdmarc: exec: %w", err)
		}
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout, target)}, nil
}

func parse(blob []byte, domain string) []types.SandboxEmittedFinding {
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	add := func(rule string, sev types.Severity, title, desc string) {
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          rule,
			Tool:            "checkdmarc",
			Severity:        sev,
			Endpoint:        domain,
			Title:           title,
			Description:     desc,
			MITRETechniques: []string{"T1566"},
		})
	}
	if !r.SPF.Valid {
		add("checkdmarc::spf-missing-or-invalid", types.SeverityMedium,
			"SPF record missing or invalid", "No valid SPF record — sender spoofing is unconstrained. "+r.SPF.Error)
	}
	switch {
	case !r.DMARC.Valid:
		add("checkdmarc::dmarc-missing-or-invalid", types.SeverityMedium,
			"DMARC record missing or invalid", "No valid DMARC policy — spoofed mail isn't rejected/quarantined. "+r.DMARC.Error)
	case strings.EqualFold(r.DMARC.Tags.P.Value, "none"):
		add("checkdmarc::dmarc-policy-none", types.SeverityLow,
			"DMARC policy is p=none", "DMARC is monitor-only (p=none); spoofed mail is reported but still delivered.")
	}
	return out
}

func init() { tool.Register(New()) }
