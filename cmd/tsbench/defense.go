package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// defense.go is the `tsbench defense` subcommand — the DEFENSIVE benchmark runner, the AI Security
// Engineer's twin of `tsbench xbow`. It loads seeded code+cloud estate scenarios (each with a known
// answer key), runs a system-under-test to REMEDIATE the estate, scores it against the post-fix oracle
// (remediation-capture = the hero metric, via retest.Verify), and appends a durable ledger line.
//
// SUBSTRATE mode (default, no LLM) runs the deterministic proposer (remediate.Propose) over the seeded
// findings — a reproducible CI baseline. AGENT mode (the LLM engineer) is the lift measured on top; its
// wiring is the honest follow-on (it needs the platform's resolveAgentLLM + a live model, like the cloud
// investigation path), so today the runner establishes the substrate baseline the agent is measured
// against. The two never share a code path in scoring — ScoreDefense grades whatever actions it is given.

func defenseCmd(argv []string) error {
	fs := flag.NewFlagSet("defense", flag.ContinueOnError)
	dir := fs.String("scenarios", "fixtures/defense", "directory of scenario dirs (each holds a scenario.json)")
	ledger := fs.String("ledger", "bench/defense-ledger.jsonl", "append-only defensive capture ledger (.jsonl)")
	out := fs.String("out", "", "also write the rendered scoreboard markdown to this path")
	mode := fs.String("mode", "substrate", "system-under-test: substrate (deterministic) | agent (LLM engineer — not yet wired here)")
	only := fs.String("only", "", "run only the scenario with this id")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *mode != "substrate" {
		return fmt.Errorf("mode %q not available in this runner yet — only 'substrate' (the deterministic baseline) is wired; agent mode is the documented follow-on (needs a live LLM, like the cloud-investigate path)", *mode)
	}

	scenarios, err := loadDefenseScenarios(*dir)
	if err != nil {
		return err
	}
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenarios found under %s (expected <dir>/<name>/scenario.json)", *dir)
	}

	var ran int
	for _, sc := range scenarios {
		if *only != "" && sc.ID != *only {
			continue
		}
		proposed := substratePropose(sc)
		score := bench.ScoreDefense(sc, proposed, nil) // substrate records no findings of its own → nil
		fmt.Println(bench.RenderDefenseScore(score))

		entry := bench.DefenseEntryFromScore(score, sc.Name, *mode)
		entry.TS = time.Now().UTC().Format(time.RFC3339)
		entry.EvidenceSHA256 = scoreEvidenceSHA(score)
		if err := bench.AppendDefenseLedger(*ledger, entry); err != nil {
			return fmt.Errorf("append ledger: %w", err)
		}
		ran++
	}
	if ran == 0 {
		return fmt.Errorf("no scenario matched --only %q", *only)
	}

	entries, err := bench.LoadDefenseLedger(*ledger)
	if err != nil {
		return fmt.Errorf("reload ledger: %w", err)
	}
	md := bench.RenderDefenseLedgerMarkdown(entries)
	fmt.Print("\n" + md)
	if *out != "" {
		if werr := os.WriteFile(*out, []byte(md), 0o644); werr != nil { //nolint:gosec // bench artifact
			return werr
		}
		fmt.Fprintf(os.Stderr, "[defense] wrote %s (%d run records)\n", *out, len(entries))
	}
	return nil
}

// defenseLedgerCmd renders the durable defensive scoreboard from the ledger without running anything.
func defenseLedgerCmd(argv []string) error {
	fs := flag.NewFlagSet("defense-ledger", flag.ContinueOnError)
	ledger := fs.String("ledger", "bench/defense-ledger.jsonl", "path to the append-only defensive ledger (.jsonl)")
	out := fs.String("out", "", "also write the rendered scoreboard markdown to this path")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	entries, err := bench.LoadDefenseLedger(*ledger)
	if err != nil {
		return fmt.Errorf("load ledger %s: %w", *ledger, err)
	}
	md := bench.RenderDefenseLedgerMarkdown(entries)
	fmt.Print(md)
	if *out != "" {
		if werr := os.WriteFile(*out, []byte(md), 0o644); werr != nil { //nolint:gosec // bench artifact
			return werr
		}
		fmt.Fprintf(os.Stderr, "[defense-ledger] wrote %s (%d run records)\n", *out, len(entries))
	}
	return nil
}

// substratePropose is the deterministic SUT: for each seeded finding, map it to the scenario asset it
// belongs to and run remediate.Propose (the SAME proposer the platform uses). This is the baseline the
// LLM engineer's lift is measured against.
func substratePropose(sc bench.DefenseScenario) []platform.Action {
	n := 0
	idgen := func() string { n++; return fmt.Sprintf("act-%d", n) }
	out := make([]platform.Action, 0, len(sc.Before))
	for _, f := range sc.Before {
		asset := assetForFinding(f, sc.Assets)
		if a, ok := remediate.Propose(f, asset, idgen); ok {
			out = append(out, a)
		}
	}
	return out
}

// assetForFinding maps a finding to the scenario asset it belongs to (longest literal target match in the
// endpoint, mirroring the platform's data-tier / per-asset attribution). Falls back to a synthetic asset
// whose type is inferred from the tool, so a scenario need not enumerate an asset for every finding.
func assetForFinding(f types.Finding, assets []platform.Asset) platform.Asset {
	best := -1
	var chosen platform.Asset
	for _, a := range assets {
		if a.Target != "" && strings.Contains(f.Endpoint, a.Target) && len(a.Target) > best {
			best = len(a.Target)
			chosen = a
		}
	}
	if best >= 0 {
		return chosen
	}
	return platform.Asset{Type: inferAssetType(f), Target: f.Endpoint}
}

// inferAssetType is the runner-local finding→asset-type map (a small, honest subset — the benchmark's
// findings are code/cloud). Mirrors crossdetect's tool routing without importing its unexported helper.
func inferAssetType(f types.Finding) string {
	switch strings.ToLower(strings.TrimSpace(f.Tool)) {
	case "prowler", "cloudfox", "scoutsuite", "scout-suite", "cloudagent":
		return "cloud_account"
	case "gitleaks", "trufflehog", "semgrep", "trivy", "grype", "osv-scanner", "checkov", "codeql", "bandit", "gosec":
		return "repository"
	case "operate":
		return "workspace"
	}
	if strings.HasPrefix(strings.ToLower(f.RuleID), "prowler::") {
		return "cloud_account"
	}
	return "repository"
}

// loadDefenseScenarios reads every <dir>/*/scenario.json into a DefenseScenario, sorted by id for a
// deterministic run order.
func loadDefenseScenarios(dir string) ([]bench.DefenseScenario, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read scenarios dir %s: %w", dir, err)
	}
	var out []bench.DefenseScenario
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name(), "scenario.json")
		raw, rerr := os.ReadFile(p) //nolint:gosec // caller-controlled bench path
		if rerr != nil {
			continue // a dir without a scenario.json is skipped, not fatal
		}
		var sc bench.DefenseScenario
		if jerr := json.Unmarshal(raw, &sc); jerr != nil {
			return nil, fmt.Errorf("parse %s: %w", p, jerr)
		}
		if sc.ID == "" {
			return nil, fmt.Errorf("%s has no id", p)
		}
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// scoreEvidenceSHA fingerprints the graded score so a ledger entry is tamper-evident + tied to a real
// artifact (§10), mirroring the XBOW ledger's evidence sha.
func scoreEvidenceSHA(s bench.DefenseScore) string {
	blob, _ := json.Marshal(s)
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}
