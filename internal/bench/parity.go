package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Differential-recall (tool-parity) harness — the way tsengine proves
// "best-in-class" for the 5 asset types that have NO neutral public
// leaderboard (api, ip_address, domain, container SCA, cloud_account).
//
// The L1 best-in-class claim (CLAUDE.md §2.4) is NOT "we beat the commercial
// scanners" — it is "per-tool recall equals the standalone OSS tool." That
// claim is provable WITHOUT any public corpus: run the wrapped tool standalone
// against a target, run it THROUGH tsengine against the same target, and
// require the orchestrated run to drop nothing the standalone tool found
// (recall == 1.0). The orchestration is the system-under-test; the standalone
// tool is the baseline.
//
//   - STANDALONE arm: `tsengine replay --tool <t>` runs ONLY that tool against
//     the target — no surface filtering, no other tools, no L1.5.
//   - THROUGH arm: a full `tsengine scan` → the tool's contribution to
//     findings_raw (captured BEFORE the L1.5 hooks, §11 — so this measures the
//     ORCHESTRATION: routing / dedup / normalize, never L1.5 demotions).
//
// This is a strict gate for single-stage assets (repository, container_image,
// cloud_account), where the tool sees the whole target both ways — any miss is
// an orchestration bug. For recon→fan-out assets (web, ip, domain, api) the
// standalone arm replays against the bare target, so a miss may instead be
// surface-coverage the fan-out deliberately pruned (informative, not always a
// regression) — read Missed accordingly.

// parityBaseline is the mandatory "competitor" cite (CLAUDE.md §14.2.2): for a
// leaderboard-less asset the neutral baseline IS the standalone OSS tool.
func parityBaseline(toolName string) Competitors {
	return Competitors{
		Leaderboard: "standalone " + toolName + " (per-tool recall parity, CLAUDE.md §2.4)",
		Note: "No neutral public leaderboard for this asset — best-in-class is proven as " +
			"recall parity with the wrapped OSS tool run standalone (delta ≥ 0), not absolute rank. " +
			"Compares findings_raw (pre-L1.5) so it isolates orchestration, not enrichment.",
	}
}

// ParityResult is the differential-recall outcome for one tool.
type ParityResult struct {
	Tool             string   `json:"tool"`
	StandaloneCount  int      `json:"standalone_count"`
	ThroughCount     int      `json:"through_count"`
	Matched          int      `json:"matched"`
	Missed           []string `json:"missed,omitempty"`  // standalone findings absent from the orchestrated run
	OrchestratorAdds int      `json:"orchestrator_adds"` // findings only the orchestrated run has (≥0, fine)
	Recall           float64  `json:"recall"`            // matched / standalone
	Pass             bool     `json:"pass"`              // true iff Missed is empty (no degradation)
}

// ParityReport wraps a result with run context + the baseline cite.
type ParityReport struct {
	Asset       string       `json:"asset"`
	Target      string       `json:"target"`
	Result      ParityResult `json:"result"`
	Competitors Competitors  `json:"competitors"`
}

// findingKey identifies a finding for cross-run comparison: rule_id + endpoint.
// Two findings are "the same" iff they name the same rule at the same location,
// so reordering or unrelated findings can't inflate or deflate recall.
func findingKey(f types.Finding) string { return f.RuleID + "|" + f.Endpoint }

// ScoreParity compares a tool's standalone findings against the same tool's
// contribution to a full orchestrated scan's findings_raw. Best-in-class
// (CLAUDE.md §2.4) requires Pass == true: the orchestration drops nothing the
// standalone tool found.
func ScoreParity(toolName string, standalone, throughRaw []types.Finding) ParityResult {
	through := map[string]struct{}{}
	for _, f := range throughRaw {
		if f.Tool == toolName {
			through[findingKey(f)] = struct{}{}
		}
	}

	seen := map[string]struct{}{}
	var missed []string
	matched := 0
	for _, f := range standalone {
		if f.Tool != "" && f.Tool != toolName {
			continue
		}
		k := findingKey(f)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		if _, ok := through[k]; ok {
			matched++
		} else {
			missed = append(missed, k)
		}
	}
	sort.Strings(missed)

	res := ParityResult{
		Tool:            toolName,
		StandaloneCount: len(seen),
		ThroughCount:    len(through),
		Matched:         matched,
		Missed:          missed,
	}
	if adds := len(through) - matched; adds > 0 {
		res.OrchestratorAdds = adds
	}
	if len(seen) == 0 {
		res.Recall = 1 // nothing to find standalone → trivially at parity
	} else {
		res.Recall = float64(matched) / float64(len(seen))
	}
	res.Pass = len(missed) == 0
	return res
}

// RenderParity formats the parity scorecard with the mandatory baseline cite.
func RenderParity(r *ParityReport) string {
	var b strings.Builder
	res := r.Result
	verdict := "PASS — at parity"
	if !res.Pass {
		verdict = fmt.Sprintf("FAIL — %d finding(s) dropped by orchestration", len(res.Missed))
	}
	fmt.Fprintf(&b, "=== tool-parity scorecard (%s · %s) ===\n", r.Asset, res.Tool)
	fmt.Fprintf(&b, "recall vs standalone: %.2f%%  (standalone=%d through=%d matched=%d, +%d orchestration-only)\n",
		res.Recall*100, res.StandaloneCount, res.ThroughCount, res.Matched, res.OrchestratorAdds)
	fmt.Fprintf(&b, "verdict: %s\n", verdict)
	if len(res.Missed) > 0 {
		fmt.Fprintf(&b, "dropped (standalone found, orchestrated run did not):\n")
		for _, m := range res.Missed {
			fmt.Fprintf(&b, "  - %s\n", m)
		}
	}
	b.WriteString(renderCompetitors(r.Competitors))
	return b.String()
}

// RunParity drives the differential test: a full orchestrated scan (THROUGH)
// and a single-tool replay against the same target (STANDALONE), then scores
// recall parity. opts.Binary is the tsengine CLI; opts.Image the sandbox image.
func RunParity(ctx context.Context, assetType, target, toolName string, opts RunOptions) (*ParityReport, error) {
	opts = opts.withDefaults()
	outDir, err := os.MkdirTemp("", "tsparity-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(outDir)

	// THROUGH arm: full orchestrated scan. gosec G204: asset/target/binary are
	// operator-supplied bench config, not finding-derived.
	scanCmd := exec.CommandContext(ctx, opts.Binary, "scan", //nolint:gosec
		"--asset", assetType, "--target", target,
		"--out", outDir, "--image", opts.Image, "--timeout", opts.Timeout)
	scanCmd.Env = append(os.Environ(), opts.Env...)
	scanCmd.Stderr = os.Stderr
	if err := scanCmd.Run(); err != nil {
		return nil, fmt.Errorf("parity: through scan: %w", err)
	}

	scanID, dashPath, err := findScanDir(outDir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(dashPath) //nolint:gosec // temp dir we created
	if err != nil {
		return nil, err
	}
	var through types.Scan
	if err := json.Unmarshal(data, &through); err != nil {
		return nil, fmt.Errorf("parity: parse through scan: %w", err)
	}

	// STANDALONE arm: replay only this tool against the same target.
	replayCmd := exec.CommandContext(ctx, opts.Binary, "replay", //nolint:gosec
		"--scan-id", scanID, "--runs", outDir, "--tool", toolName,
		"--target", target, "--image", opts.Image)
	replayCmd.Env = append(os.Environ(), opts.Env...)
	replayCmd.Stderr = os.Stderr
	rawOut, err := replayCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("parity: standalone replay: %w", err)
	}
	var resp struct {
		Findings []types.Finding `json:"findings"`
	}
	if err := json.Unmarshal(rawOut, &resp); err != nil {
		return nil, fmt.Errorf("parity: parse replay output: %w", err)
	}

	return &ParityReport{
		Asset:       assetType,
		Target:      target,
		Result:      ScoreParity(toolName, resp.Findings, through.FindingsRaw),
		Competitors: parityBaseline(toolName),
	}, nil
}

// findScanDir returns the scan_id (the single subdir name) and the path to its
// vulnerabilities.json under outDir.
func findScanDir(outDir string) (string, string, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return "", "", err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(outDir, e.Name(), "vulnerabilities.json")
		if _, err := os.Stat(p); err == nil {
			return e.Name(), p, nil
		}
	}
	return "", "", fmt.Errorf("parity: no vulnerabilities.json under %s", outDir)
}
