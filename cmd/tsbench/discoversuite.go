package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// discoversuite.go is `tsbench discover-suite` — the CONSOLIDATION runner for the impact-discovery axis. It
// loads every scenario in a directory and, per scenario, self-validates that it is well-formed + actually
// discriminating: the ORACLE answer (exactly the high-impact ids) must PASS, and FLAG-EVERYTHING must raise
// false alarms (proving the scenario tests precision, not just recall). It prints one scorecard covering the
// whole finding axis + the impact-category coverage. This is the deterministic integrity check; the LIVE AI
// engineer numbers (recall/precision 100% via the proxy) are recorded per scenario in the ledgers + README.
//
// It renders NO SUT-specific logic (anti-overfit §14.2): it consumes only the authored HighImpact facts.

func discoverSuiteCmd(argv []string) error {
	fs := flag.NewFlagSet("discover-suite", flag.ContinueOnError)
	dir := fs.String("dir", "fixtures/discovery", "directory of discovery scenario JSONs")
	strict := fs.Bool("strict", false, "exit non-zero if any scenario is not well-formed + discriminating")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	entries, err := filepath.Glob(filepath.Join(*dir, "*.json"))
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("no scenarios in %s", *dir)
	}
	sort.Strings(entries)

	type row struct {
		id            string
		findings      int
		impacts       int
		categories    []string
		oraclePass    bool
		flagAllFP     int
		wellFormed    bool // oracle passes AND flag-all raises >=1 false alarm (tests precision)
	}
	var rows []row
	catTotals := map[bench.ImpactType]int{}
	allOK := true

	for _, path := range entries {
		raw, rerr := os.ReadFile(path) //nolint:gosec // bench fixture dir
		if rerr != nil {
			return rerr
		}
		var sc bench.DiscoveryScenario
		if jerr := json.Unmarshal(raw, &sc); jerr != nil {
			return fmt.Errorf("%s: %w", filepath.Base(path), jerr)
		}
		oracle := bench.ScoreDiscovery(sc, bench.OracleDiscovery(sc))
		flagAll := bench.ScoreDiscovery(sc, bench.FlagAllDiscovery(sc))
		cats := make([]string, 0, len(oracle.ByType))
		for t, tr := range oracle.ByType {
			cats = append(cats, fmt.Sprintf("%s:%d", t, tr.Total))
			catTotals[t] += tr.Total
		}
		sort.Strings(cats)
		wf := oracle.Pass() && flagAll.FP > 0
		if !wf {
			allOK = false
		}
		rows = append(rows, row{
			id: sc.ID, findings: len(sc.Findings), impacts: oracle.TP + oracle.FN,
			categories: cats, oraclePass: oracle.Pass(), flagAllFP: flagAll.FP, wellFormed: wf,
		})
	}

	fmt.Println("Impact-discovery suite — deterministic integrity scorecard")
	fmt.Println("(oracle=perfect answer must PASS · flag-all FP>0 proves the scenario tests precision)")
	fmt.Println()
	fmt.Printf("%-22s %8s %8s %8s %10s   %s\n", "scenario", "findings", "impacts", "oracle", "flagAll-FP", "categories")
	fmt.Println(strings.Repeat("-", 92))
	for _, r := range rows {
		ok := "PASS"
		if !r.oraclePass {
			ok = "FAIL"
		}
		flag := "well-formed"
		if !r.wellFormed {
			flag = "NOT-DISCRIMINATING"
		}
		fmt.Printf("%-22s %8d %8d %8s %10d   %s  [%s]\n",
			r.id, r.findings, r.impacts, ok, r.flagAllFP, strings.Join(r.categories, " "), flag)
	}
	fmt.Println(strings.Repeat("-", 92))
	cats := make([]string, 0, len(catTotals))
	for t, n := range catTotals {
		cats = append(cats, fmt.Sprintf("%s:%d", t, n))
	}
	sort.Strings(cats)
	fmt.Printf("%d scenarios · impact-category coverage: %s\n", len(rows), strings.Join(cats, " "))
	if allOK {
		fmt.Println("ALL scenarios well-formed + discriminating (oracle passes, precision is tested).")
	} else {
		fmt.Println("WARNING: one or more scenarios are not discriminating (see NOT-DISCRIMINATING above).")
	}
	if *strict && !allOK {
		return fmt.Errorf("not all scenarios are well-formed + discriminating")
	}
	return nil
}
