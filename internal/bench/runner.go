package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// RunOptions configures how the harness invokes the engine.
type RunOptions struct {
	Binary  string   // path to the tsengine binary (default ./bin/tsengine)
	Image   string   // sandbox image
	Timeout string   // per-scan timeout flag value (e.g. "240s")
	Trials  int      // repeat count (default 1)
	Env     []string // extra env (e.g. TSENGINE_L15_DISABLED=1)
}

func (o RunOptions) withDefaults() RunOptions {
	if o.Binary == "" {
		o.Binary = "./bin/tsengine"
	}
	if o.Image == "" {
		o.Image = "tsengine/sandbox:0.1.0"
	}
	if o.Timeout == "" {
		o.Timeout = "300s"
	}
	if o.Trials < 1 {
		o.Trials = 1
	}
	return o
}

// RunResult is the harness output for one fixture: per-trial scores plus
// recall/enrichment trial statistics.
type RunResult struct {
	Fixture       string     `json:"fixture"`
	Scores        []Score    `json:"scores"`
	RecallStats   TrialStats `json:"recall_stats"`
	EnrichStats   TrialStats `json:"enrichment_stats"`
	AllPass       bool       `json:"all_pass"`
}

// Run executes a fixture N times via the real tsengine binary and scores
// each trial. Subprocessing the binary means the bench exercises the
// whole stack — sandbox boundary, orchestrator, L1.5 chain, dashboard —
// exactly as a user would.
func Run(ctx context.Context, f *Fixture, opts RunOptions) (*RunResult, error) {
	opts = opts.withDefaults()
	res := &RunResult{Fixture: f.Name, AllPass: true}
	var recalls, enrich []float64

	for i := 0; i < opts.Trials; i++ {
		scan, err := runOnce(ctx, f, opts)
		if err != nil {
			return nil, fmt.Errorf("bench: trial %d: %w", i+1, err)
		}
		sc := ScoreScan(f, scan)
		res.Scores = append(res.Scores, sc)
		recalls = append(recalls, sc.DetectionRecall)
		enrich = append(enrich, sc.EnrichmentCov)
		if !sc.Pass {
			res.AllPass = false
		}
	}
	res.RecallStats = stats(recalls)
	res.EnrichStats = stats(enrich)
	return res, nil
}

// runOnce runs the engine once and returns the parsed scan.
func runOnce(ctx context.Context, f *Fixture, opts RunOptions) (*types.Scan, error) {
	outDir, err := os.MkdirTemp("", "tsbench-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(outDir)

	// gosec G204: opts.Binary + args come from internal bench config (operator
	// supplies them on the CLI), not from a finding/scan target.
	cmd := exec.CommandContext(ctx, opts.Binary, "scan", //nolint:gosec
		"--asset", f.Asset,
		"--target", f.Target,
		"--out", outDir,
		"--image", opts.Image,
		"--timeout", opts.Timeout,
	)
	cmd.Env = append(os.Environ(), opts.Env...)
	cmd.Stderr = os.Stderr // surface scan progress
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("engine run: %w", err)
	}

	path, err := findVulnJSON(outDir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // temp dir we created
	if err != nil {
		return nil, err
	}
	var scan types.Scan
	if err := json.Unmarshal(data, &scan); err != nil {
		return nil, fmt.Errorf("parse scan output: %w", err)
	}
	return &scan, nil
}

func findVulnJSON(outDir string) (string, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			p := filepath.Join(outDir, e.Name(), "vulnerabilities.json")
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("bench: no vulnerabilities.json under %s", outDir)
}

// Ablation runs a fixture with L1.5 enabled and disabled, returning both
// results so the report can show the L1.5 lift (CLAUDE.md §14.1). The
// headline delta is enrichment coverage: ~N% enabled → 0 disabled.
type Ablation struct {
	Enabled  *RunResult `json:"l15_enabled"`
	Disabled *RunResult `json:"l15_disabled"`
}

// RunAblation runs both arms. Detection recall should be ~unchanged
// (L1.5 is translation, not detection); enrichment coverage should drop
// to zero when disabled — that contrast IS the L1.5-lift measurement.
func RunAblation(ctx context.Context, f *Fixture, opts RunOptions) (*Ablation, error) {
	enabled, err := Run(ctx, f, opts)
	if err != nil {
		return nil, fmt.Errorf("ablation (enabled): %w", err)
	}
	off := opts
	off.Env = append(append([]string(nil), opts.Env...), "TSENGINE_L15_DISABLED=1")
	disabled, err := Run(ctx, f, off)
	if err != nil {
		return nil, fmt.Errorf("ablation (disabled): %w", err)
	}
	return &Ablation{Enabled: enabled, Disabled: disabled}, nil
}
