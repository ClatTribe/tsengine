// Package osvscanner wraps Google's osv-scanner (OSV.dev-backed SCA) as a
// tsengine Tool for the repository asset. It's a THIRD lockfile/SCA source
// alongside trivy fs + grype — three independent vuln databases give the
// L1.5 corroborator strong cross-source agreement. Registers via init().
package osvscanner

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

// OSVScanner is the tool.Tool implementation.
type OSVScanner struct{}

// New constructs an OSVScanner wrapper.
func New() *OSVScanner { return &OSVScanner{} }

func (*OSVScanner) Name() string              { return "osv-scanner" }
func (*OSVScanner) SandboxExecution() bool    { return true }
func (*OSVScanner) MITRETechniques() []string { return []string{"T1195.001"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*OSVScanner) KnownArgs() []string { return []string{"target"} }

// Run scans a directory tree's lockfiles for known vulnerabilities.
//
//	"target" string — required, the path to scan (the workspace mount).
func (*OSVScanner) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("osv-scanner: missing required arg 'target'")
	}
	// `osv-scanner scan` (v2) recurses by default; --format json to stdout.
	cmd := exec.CommandContext(ctx, "osv-scanner", "scan", "--format", "json", "-r", target)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("osv-scanner: exec: %w", err)
		}
		// osv-scanner exits 1 when vulns are found — parse anyway.
	}
	return tool.Result{Output: string(stdout), Findings: parse(stdout)}, nil
}

// osvReport mirrors the subset of osv-scanner's JSON we consume.
type osvReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID       string   `json:"id"`
				Summary  string   `json:"summary"`
				Aliases  []string `json:"aliases"`
				Affected []struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
					Ranges []struct {
						Events []struct {
							Introduced string `json:"introduced"`
							Fixed      string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	var r osvReport
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, res := range r.Results {
		for _, p := range res.Packages {
			pkg := fmt.Sprintf("%s@%s", p.Package.Name, p.Package.Version)
			for _, v := range p.Vulnerabilities {
				// Put the CVE in the RuleID when one exists (preferred over
				// the GHSA/OSV id) so the L1.5 corroborator + threat_intel
				// hooks — which extract CVEs from RuleID — agree across
				// trivy/grype/osv-scanner on the same package-CVE.
				id := preferCVE(v.ID, v.Aliases)
				// Fix availability (competitor-parity signal): OSV records the patched version in
				// affected[].ranges[].events[].fixed. Extract it (preferring the range for THIS
				// package) so the enriched view / VAPT report can lead with fixable vulns.
				var fixedVer string
				for _, a := range v.Affected {
					if a.Package.Name != "" && !strings.EqualFold(a.Package.Name, p.Package.Name) {
						continue
					}
					for _, rng := range a.Ranges {
						for _, e := range rng.Events {
							if e.Fixed != "" {
								fixedVer = e.Fixed
								break
							}
						}
						if fixedVer != "" {
							break
						}
					}
					if fixedVer != "" {
						break
					}
				}
				out = append(out, types.SandboxEmittedFinding{
					RuleID:          "osv-scanner::" + id,
					Tool:            "osv-scanner",
					Severity:        types.SeverityMedium,
					Endpoint:        pkg,
					Title:           fmt.Sprintf("%s in %s (%s)", id, pkg, p.Package.Ecosystem),
					Description:     withFixNote(v.Summary, fixedVer),
					MITRETechniques: []string{"T1195.001"},
					ToolArgs:        map[string]string{"ecosystem": p.Package.Ecosystem, "source": res.Source.Path, "osv_id": v.ID, "fixable": boolStr(fixedVer != ""), "fixed_version": fixedVer},
				})
			}
		}
	}
	return out
}

// withFixNote appends a concise, grounded fix-availability line to a finding description — the
// competitor-parity "fixable vs no-fix" signal, immediately visible in the VAPT report / issue detail.
func withFixNote(desc, fixedVer string) string {
	if fixedVer != "" {
		return strings.TrimSpace(desc + "\nFix available: upgrade to " + fixedVer + ".")
	}
	return strings.TrimSpace(desc + "\nNo fixed version available yet — mitigate (pin/replace/isolate) until upstream patches.")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// preferCVE returns the first CVE alias if present, else the native OSV id.
func preferCVE(id string, aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return id
}

func init() { tool.Register(New()) }
