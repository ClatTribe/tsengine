package l2

import (
	"context"
	"strings"
)

// External-service interfaces — the seam to real-time data + re-dispatch +
// live verification. Production wires adapters (threat-intel corpus,
// compliance corpus, the /replay handler, an HTTP client); tests wire
// mocks. All return rendered TEXT (the tool result the LLM reads), keeping
// the agent decoupled from the concrete data shapes.

// ThreatIntelLookup answers CVE → CVSS/KEV/EPSS/advisory summary (§2.7:
// real-time data past the model's training cutoff).
type ThreatIntelLookup interface {
	LookupCVE(ctx context.Context, cve string) (summary string, found bool)
}

// ComplianceLookup answers CWE-set → affected control summary (SOC2/PCI/…).
type ComplianceLookup interface {
	MapCWE(cwes []string) (summary string)
}

// Prober re-fires a deterministic L1/registry tool via /replay — the
// LLM-can't-run-subprocess §2.7 tool. This is L2's depth lever (vs. raw
// shell). Returns a rendered summary of the probe's findings.
type Prober interface {
	Probe(ctx context.Context, tool string, args map[string]any) (summary string, err error)
}

// HTTPDoer issues one HTTP request (verification only — confirm a
// pattern_match without re-crafting an exploit). Returns a rendered
// status+headers+truncated-body summary.
type HTTPDoer interface {
	Do(ctx context.Context, method, url string, headers map[string]string, body string) (summary string, err error)
}

// externalTools builds the fetch-external / re-dispatch / primitive tools —
// the §2.7 tools whose existence is justified by the model's hands being
// short: real-time data past the training cutoff (threat-intel/compliance),
// re-triggering a deterministic scan (probe), and network I/O (send_request).
//
// Each tool is included ONLY if its backing service is wired. A partial Deps
// (e.g. tests with just a Prober) still yields a valid, smaller catalog —
// the cap is per-phase ≤12 and the full set is ~10, so this never overflows.
func externalTools(d Deps) Catalog {
	var c Catalog

	if d.ThreatIntel != nil {
		ti := d.ThreatIntel
		c = append(c, Tool{
			Schema: ToolSchema{
				Name: "query_threat_intel",
				Description: "Look up live CVSS / KEV / EPSS / advisory data for a CVE (real-time, past the model's training cutoff). " +
					"Use it to prioritize: a KEV-listed, high-EPSS CVE outranks a higher-CVSS one nobody's exploiting.",
				Params: obj(map[string]any{
					"cve": str("the CVE id, e.g. CVE-2021-44228"),
				}, "cve"),
			},
			Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
				cve := strings.TrimSpace(argStr(args, "cve"))
				if cve == "" {
					return ToolResult{Err: true, Content: "cve is required, e.g. CVE-2021-44228"}, nil
				}
				summary, found := ti.LookupCVE(ctx, cve)
				if !found {
					return ToolResult{Err: true, Content: "no threat-intel record for " + cve + " in the pinned corpus"}, nil
				}
				return ToolResult{Content: summary}, nil
			},
		})
	}

	if d.Compliance != nil {
		cl := d.Compliance
		c = append(c, Tool{
			Schema: ToolSchema{
				Name: "lookup_compliance_mapping",
				Description: "Map a finding's CWE(s) to the compliance controls they affect (SOC2 / PCI / HIPAA / CIS / NIST). " +
					"Use it to phrase remediation in the customer's audit language.",
				Params: obj(map[string]any{
					"cwe": strArr("CWE ids to map, e.g. [\"CWE-89\"]"),
				}, "cwe"),
			},
			Handler: func(_ context.Context, args map[string]any, _ *State) (ToolResult, error) {
				cwes := argStrList(args, "cwe")
				if len(cwes) == 0 {
					return ToolResult{Err: true, Content: "cwe is required — pass the CWE id(s) from the finding"}, nil
				}
				summary := cl.MapCWE(cwes)
				if strings.TrimSpace(summary) == "" {
					return ToolResult{Content: "no compliance controls map to " + strings.Join(cwes, ", ")}, nil
				}
				return ToolResult{Content: summary}, nil
			},
		})
	}

	if d.Prober != nil {
		pr := d.Prober
		c = append(c, Tool{
			Schema: ToolSchema{
				Name: "dispatch_l2_probe",
				Description: "Re-fire a deterministic L1/registry tool for depth (routes through /replay — the LLM can't run subprocesses). " +
					"Use it to CONFIRM or deepen an existing finding (e.g. sqlmap on a suspected SQLi), not to craft an exploit. " +
					"The result is evidence you can cite via update_finding(verified_by).",
				Params: obj(map[string]any{
					"tool": str("the tool to replay, e.g. sqlmap, nuclei, ffuf"),
					"args": objParam("tool-specific args (include target/url, templates, tamper, etc.)"),
				}, "tool"),
			},
			Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
				tool := strings.TrimSpace(argStr(args, "tool"))
				if tool == "" {
					return ToolResult{Err: true, Content: "tool is required, e.g. sqlmap"}, nil
				}
				summary, err := pr.Probe(ctx, tool, argMap(args, "args"))
				if err != nil {
					return ToolResult{Err: true, Content: "probe failed: " + err.Error()}, nil
				}
				return ToolResult{Content: summary}, nil
			},
		})
	}

	if d.HTTP != nil {
		hc := d.HTTP
		c = append(c, Tool{
			Schema: ToolSchema{
				Name: "send_request",
				Description: "Issue ONE HTTP request to verify a finding (the LLM can't do network I/O). " +
					"Use it to confirm a pattern_match — e.g. re-request a reflected-XSS URL and check the payload echoes back. " +
					"This is a verification primitive, not an exploitation tool: confirm, don't weaponize.",
				Params: obj(map[string]any{
					"method":  enumStr("HTTP method (default GET)", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"),
					"url":     str("absolute URL to request"),
					"headers": objParam("optional request headers, e.g. {\"Cookie\": \"...\"}"),
					"body":    str("optional request body"),
				}, "url"),
			},
			Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
				url := strings.TrimSpace(argStr(args, "url"))
				if url == "" {
					return ToolResult{Err: true, Content: "url is required (absolute)"}, nil
				}
				method := strings.ToUpper(strings.TrimSpace(argStr(args, "method")))
				if method == "" {
					method = "GET"
				}
				summary, err := hc.Do(ctx, method, url, argStrMap(args, "headers"), argStr(args, "body"))
				if err != nil {
					return ToolResult{Err: true, Content: "request failed: " + err.Error()}, nil
				}
				return ToolResult{Content: summary}, nil
			},
		})
	}

	// The generalist delegates cloud-depth to the cloud SPECIALIST (cloudagent over the tenant's stored
	// cloud snapshot). Added ONLY when wired (a Free/no-cloud tenant never sees it → the ≤12 cap holds).
	if d.CloudInvestigator != nil {
		ci := d.CloudInvestigator
		c = append(c, Tool{
			Schema: ToolSchema{
				Name: "investigate_cloud",
				Description: "Run the cloud security specialist over the tenant's cloud inventory for DEEP " +
					"cloud-graph reasoning (IAM effective permissions, network reachability, privilege " +
					"escalation, proven attack paths) beyond the estate summary. Use it when an issue touches " +
					"cloud and you need exploitable paths a crown jewel. Returns the specialist's proven paths.",
				Params: obj(map[string]any{
					"focus": str("what to investigate, e.g. 'paths to the production database' or a cloud finding/resource"),
				}, "focus"),
			},
			Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
				out, err := ci(ctx, strings.TrimSpace(argStr(args, "focus")))
				if err != nil {
					return ToolResult{Err: true, Content: "cloud investigation failed: " + err.Error()}, nil
				}
				return ToolResult{Content: out}, nil
			},
		})
	}

	return c
}
