package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// leadCmd drives the AI SECURITY ENGINEER (the L2 Lead) over a saved scan's
// enriched findings — the engineer-side counterpart of web-investigate, and the
// measurement harness for the harness-improvement program's Engineer lane
// (docs/harness-improvement-program.md). Output: the Lead's Outcome (emitted
// reports with cited evidence ids) as JSON — the autopsy layer compares citations
// vs L1 ids, severity agreement, and drop decisions per finding.
func leadCmd(argv []string) error {
	fs := flag.NewFlagSet("leadrun", flag.ContinueOnError)
	scanPath := fs.String("scan", "", "path to vulnerabilities.json from tsengine scan (REQUIRED)")
	out := fs.String("out", "", "write the Lead Outcome JSON here")
	maxIters := fs.Int("max-iters", 24, "Lead loop cap")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *scanPath == "" {
		return fmt.Errorf("--scan is required")
	}
	raw, err := os.ReadFile(*scanPath)
	if err != nil {
		return err
	}
	var scan types.Scan
	if err := json.Unmarshal(raw, &scan); err != nil {
		return fmt.Errorf("parse scan: %w", err)
	}
	findings := scan.FindingsEnriched
	if len(findings) == 0 {
		findings = scan.FindingsRaw
	}
	if len(findings) == 0 {
		return fmt.Errorf("scan has no findings to triage")
	}

	// Keyless proxy first: an opencode serve endpoint drives the Lead through the SAME
	// free-tier brains the pentester uses (prompt-side tool-calling bridge). Native
	// tool-calling providers still win when explicitly configured below.
	var client l2.Client
	if oc := l2.OpenCodeClientFromEnv(); oc != nil {
		client = oc
	} else {
		client = l2.ClientFromEnv()
	}
	if client == nil {
		return fmt.Errorf("leadrun needs a tool-calling LLM: set LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen3:8b (local Ollama), or ANTHROPIC_API_KEY")
	}

	fmt.Fprintln(os.Stderr, "[leadrun] building catalog…")
	catalog := l2.BuildCatalog(l2.Deps{L1Findings: findings})
	fmt.Fprintln(os.Stderr, "[leadrun] starting Lead run…")
	agent, err := l2.New(client, catalog, l2.Budget{
		MaxCostUSD:     2.0,
		MaxIterations:  *maxIters,
		KeepRecentMsgs: 8,
	})
	if err != nil {
		return err
	}
	asset := scan.Asset
	outcome, err := agent.Run(context.Background(), asset, findings)
	if err != nil {
		return err
	}
	blob, _ := json.MarshalIndent(struct {
		ScanID      string      `json:"scan_id"`
		AssetType   string      `json:"asset_type"`
		L1Count     int         `json:"l1_findings"`
		Model       string      `json:"model"`
		StopReason  string      `json:"stop_reason"`
		Iterations  int         `json:"iterations"`
		CostUSD     float64     `json:"cost_usd"`
		Emitted     []l2Emitted `json:"emitted_reports"`
		CitedL1IDs  []string    `json:"cited_l1_ids"`
		DroppedL1ID []string    `json:"dropped_l1_ids"`
	}{scan.ScanID, string(asset.Type), len(findings), outcome.Model,
		string(outcome.StopReason), outcome.Iterations, outcome.CostUSD,
		emittedOf(outcome), citedIDs(outcome), droppedIDs(findings, citedIDs(outcome))}, "", "  ")
	if *out != "" {
		if werr := os.WriteFile(*out, blob, 0o644); werr != nil {
			return werr
		}
		fmt.Fprintf(os.Stderr, "[leadrun] outcome → %s\n", *out)
	}
	fmt.Println(renderLead(outcome, findings))
	return nil
}

type l2Emitted struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Cited    []string `json:"cited"`
}

func emittedOf(o l2.Outcome) []l2Emitted {
	out := make([]l2Emitted, 0, len(o.Findings))
	for _, f := range o.Findings {
		var cited []string
		if f.L2 != nil {
			cited = f.L2.EvidenceIDs
		}
		out = append(out, l2Emitted{f.ID, string(f.Severity), f.Title, cited})
	}
	return out
}

func citedIDs(o l2.Outcome) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range o.Findings {
		if f.L2 == nil {
			continue
		}
		for _, id := range f.L2.EvidenceIDs {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// droppedIDs lists L1 findings the Lead never cited — its implicit "dismissed"
// decisions, which the autopsy grades against decoy/severity expectations.
func droppedIDs(l1 []types.Finding, cited []string) []string {
	set := map[string]bool{}
	for _, c := range cited {
		set[c] = true
	}
	var out []string
	for _, f := range l1 {
		if !set[f.ID] {
			out = append(out, f.ID)
		}
	}
	return out
}

func renderLead(o l2.Outcome, l1 []types.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== AI SECURITY ENGINEER — triage over %d L1 finding(s) ===\n", len(l1))
	fmt.Fprintf(&b, "model=%s stop=%s iters=%d cost=$%.4f\n", o.Model, o.StopReason, o.Iterations, o.CostUSD)
	for _, f := range o.Findings {
		sev := ""
		if f.L2 != nil {
			sev = string(f.L2.Verification)
		}
		fmt.Fprintf(&b, "[%s] %s (%s) ← cites %v\n  %s\n", f.Severity, f.Title, sev,
			func() []string {
				if f.L2 != nil {
					return f.L2.EvidenceIDs
				}
				return nil
			}(), firstLine(f.Description))
	}
	return b.String()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
