// Package govulncheck wraps the Go team's official govulncheck as a
// tsengine depth Tool for the repository asset — the grounded answer to
// SCA's #1 false-positive source: REACHABILITY.
//
// trivy / grype / osv-scanner flag every CVE in every dependency, reachable
// or not — high recall, but a flood of findings for vulnerable code that is
// never called. govulncheck does call-graph analysis and reports only the
// vulnerabilities whose vulnerable symbol is actually reachable from the
// module's code. Those findings are therefore the high-confidence,
// low-false-positive subset; they corroborate (and prioritise) the SCA tools'
// raw CVE list rather than replacing it (the L1 raw recall is unchanged).
//
// Go-specific by nature (call-graph analysis needs the Go toolchain + module),
// so it fires from the repository escalation stage only when the tree looks
// like a Go project. See docs/adr/0003-sca-reachability-govulncheck.md for the
// sandbox Go-toolchain requirement. Registers via init().
package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// GoVulnCheck is the tool.Tool implementation.
type GoVulnCheck struct{}

// New constructs a GoVulnCheck wrapper.
func New() *GoVulnCheck { return &GoVulnCheck{} }

func (*GoVulnCheck) Name() string              { return "govulncheck" }
func (*GoVulnCheck) SandboxExecution() bool    { return true }
func (*GoVulnCheck) MITRETechniques() []string { return []string{"T1190"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*GoVulnCheck) KnownArgs() []string { return []string{"target"} }

// Run analyses the Go module rooted at "target" (the workspace mount).
func (*GoVulnCheck) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("govulncheck: missing required arg 'target'")
	}
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = target
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	// govulncheck exits 3 when it FINDS reachable vulnerabilities — a
	// successful run, not an error. Only a non-ExitError (binary missing /
	// toolchain absent / context cancelled) is a real failure; parse stdout
	// regardless. Degrades gracefully (no findings) when unavailable.
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "govulncheck: " + err.Error()}, nil
		}
	}
	out := stdout.Bytes()
	return tool.Result{Output: string(out), Findings: parse(out)}, nil
}

// govulncheck -json emits a STREAM of JSON objects, each populating exactly
// one of these fields. We decode the stream and keep only osv definitions and
// findings; a finding is "called" (reachable) when its trace's most-specific
// frame names a function.
type message struct {
	OSV     *osvEntry `json:"osv,omitempty"`
	Finding *finding  `json:"finding,omitempty"`
}

type osvEntry struct {
	ID      string   `json:"id"`      // e.g. GO-2023-1234
	Aliases []string `json:"aliases"` // includes CVE-… ids
	Summary string   `json:"summary"`
}

type finding struct {
	OSV   string  `json:"osv"`
	Trace []frame `json:"trace"`
}

type frame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	dec := json.NewDecoder(bytes.NewReader(blob))
	osvByID := map[string]osvEntry{}
	calledFrame := map[string]frame{} // osv id → the reachable frame (first seen)
	var order []string

	for {
		var m message
		if err := dec.Decode(&m); err != nil {
			break // EOF or a malformed tail — stop, keep what parsed
		}
		switch {
		case m.OSV != nil:
			osvByID[m.OSV.ID] = *m.OSV
		case m.Finding != nil && len(m.Finding.Trace) > 0:
			// trace[0] is the most-specific frame (the vulnerable symbol). A
			// non-empty Function there means the vuln is CALLED — reachable.
			// Module/package-only traces are "imported but not called" → the
			// false-positive class we deliberately drop.
			top := m.Finding.Trace[0]
			if top.Function == "" {
				continue
			}
			if _, seen := calledFrame[m.Finding.OSV]; !seen {
				calledFrame[m.Finding.OSV] = top
				order = append(order, m.Finding.OSV)
			}
		}
	}

	out := make([]types.SandboxEmittedFinding, 0, len(order))
	for _, id := range order {
		osv := osvByID[id]
		fr := calledFrame[id]
		endpoint := fr.Package
		if endpoint == "" {
			endpoint = fr.Module
		}
		title := osv.Summary
		if title == "" {
			title = id
		}
		out = append(out, types.SandboxEmittedFinding{
			// CVE (when known) rides in the rule_id so the L1.5 threat_intel
			// hook enriches it (KEV/EPSS) — matching trivy/grype.
			RuleID:          "govulncheck::" + preferredID(id, osv.Aliases),
			Tool:            "govulncheck",
			Severity:        types.SeverityHigh, // call-reachable known vuln → actionable
			Endpoint:        endpoint,
			Title:           "Call-reachable vulnerability: " + title,
			MITRETechniques: []string{"T1190"},
		})
	}
	return out
}

// preferredID prefers a CVE alias (so threat_intel can enrich) over the GO id.
func preferredID(goID string, aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			return a
		}
	}
	return goID
}

func init() { tool.Register(New()) }
