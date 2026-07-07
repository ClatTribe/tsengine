package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// TestDiscoverFromScan_RealFixtures runs the END-TO-END pipeline over the committed scan fixtures and asserts
// the engine-derived ground truth matches expectation: the acme scan yields exactly the code→cloud chain (2
// impacts), and the clean scan yields none (no cross-surface chain → 0 impacts → flag-nothing is correct).
// Guards the fixtures + the EstateFromFindings bridge against regression. No LLM — pure pipeline.
func TestDiscoverFromScan_RealFixtures(t *testing.T) {
	cases := []struct {
		file        string
		wantImpacts int
		wantChains  int
	}{
		{"../../fixtures/discovery-scans/scan-acme.json", 2, 1},
		{"../../fixtures/discovery-scans/scan-clean.json", 0, 0},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			raw, err := os.ReadFile(c.file)
			if err != nil {
				t.Fatal(err)
			}
			var in bench.ScanInput
			if jerr := json.Unmarshal(raw, &in); jerr != nil {
				t.Fatalf("parse: %v", jerr)
			}
			sc, chains := bench.EstateFromFindings("t", in)
			if len(chains) != c.wantChains {
				t.Errorf("chains: got %d want %d", len(chains), c.wantChains)
			}
			got := 0
			for _, f := range sc.Findings {
				if f.HighImpact {
					got++
				}
			}
			if got != c.wantImpacts {
				t.Errorf("impacts: got %d want %d", got, c.wantImpacts)
			}
			// the engine-derived oracle answer must always score a clean PASS (self-consistent pipeline).
			if s := bench.ScoreDiscovery(sc, bench.OracleDiscovery(sc)); !s.Pass() {
				t.Errorf("oracle over engine-derived estate must PASS: %s", bench.RenderDiscoveryScore(s))
			}
		})
	}
}
