package operate

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadWorkspace reads a Workspace snapshot (an IdP / Google Workspace / M365 export) from
// a JSON file. This is the boundary a live connector produces — keeping the posture
// logic snapshot-driven keeps it deterministic + testable (mirrors cloudgraph.LoadSnapshot).
func LoadWorkspace(path string) (Workspace, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return Workspace{}, err
	}
	var ws Workspace
	if err := json.Unmarshal(data, &ws); err != nil {
		return Workspace{}, fmt.Errorf("operate: decode workspace %s: %w", path, err)
	}
	return ws, nil
}
