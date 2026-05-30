package cloudengine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// EmitScenario writes ONE synthetic emulated cloud account to disk: the
// inventory JSON at path (what `tsengine cloud-assess --snapshot` / `scan
// --snapshot` consume) and the scenario's prowler findings at
// "<path-without-ext>.prowler.json" (for the corroborate/downgrade dual-view).
// This lets the full pipeline — ingest → deterministic engine → LLM translator
// — be exercised end-to-end on a synthetic, ground-truth-verified account, with
// no real cloud (docs/design §6, Tier 2).
func EmitScenario(path string, seed int64, nReal, nDecoy int, withPrivesc bool) error {
	scn := Generate(seed, nReal, nDecoy, withPrivesc)
	if err := scn.Verify(); err != nil {
		return fmt.Errorf("emit: generated scenario failed verify: %w", err)
	}

	inv := scn.Snapshot.ToInventory()
	invJSON, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, invJSON, 0o600); err != nil {
		return fmt.Errorf("emit: write inventory: %w", err)
	}

	prowlerPath := strings.TrimSuffix(path, ".json") + ".prowler.json"
	prowlerJSON, err := json.MarshalIndent(scn.Prowler, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(prowlerPath, prowlerJSON, 0o600); err != nil {
		return fmt.Errorf("emit: write prowler findings: %w", err)
	}

	fmt.Fprintf(os.Stderr,
		"[emit] synthetic emulated account → %s (+ %s)\n  ground truth: %d real path(s), %d decoy(s)\n",
		path, prowlerPath, len(scn.RealTargets), len(scn.DecoyFindings))
	return nil
}
