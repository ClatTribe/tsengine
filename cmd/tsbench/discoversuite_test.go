package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// TestDiscoverSuite_FixturesWellFormed loads the REAL committed discovery fixtures and asserts each is
// well-formed + discriminating: the oracle (perfect) answer PASSES, and flagging everything raises at least
// one false alarm (so the scenario genuinely tests precision, not just recall). This guards the whole
// impact-discovery axis against a fixture regressing into a non-discriminating or unsatisfiable state.
func TestDiscoverSuite_FixturesWellFormed(t *testing.T) {
	paths, err := filepath.Glob("../../fixtures/discovery/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 6 {
		t.Fatalf("expected the full discovery suite (>=6 scenarios), found %d", len(paths))
	}
	for _, p := range paths {
		p := p
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, rerr := os.ReadFile(p)
			if rerr != nil {
				t.Fatal(rerr)
			}
			var sc bench.DiscoveryScenario
			if jerr := json.Unmarshal(raw, &sc); jerr != nil {
				t.Fatalf("parse: %v", jerr)
			}
			if sc.ID == "" || len(sc.Findings) == 0 {
				t.Fatal("scenario needs an id + findings")
			}
			oracle := bench.ScoreDiscovery(sc, bench.OracleDiscovery(sc))
			if !oracle.Pass() {
				t.Errorf("oracle (perfect) answer must PASS: %s", bench.RenderDiscoveryScore(oracle))
			}
			flagAll := bench.ScoreDiscovery(sc, bench.FlagAllDiscovery(sc))
			if flagAll.FP == 0 {
				t.Errorf("flag-everything must raise a false alarm — scenario has no noise, so it doesn't test precision")
			}
		})
	}
}
