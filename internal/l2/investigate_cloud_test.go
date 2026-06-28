package l2

import (
	"context"
	"testing"
)

func findCloudTool(c Catalog, name string) (Tool, bool) {
	for _, t := range c {
		if t.Schema.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// TestInvestigateCloudTool_ConditionalAndDelegates: the cloud-delegation tool is exposed ONLY when a
// CloudInvestigator is wired (so the ≤12 cap is never spent on a dead tool), the catalog still validates
// under the cap when it IS added, and the tool's handler delegates to the injected closure.
func TestInvestigateCloudTool_ConditionalAndDelegates(t *testing.T) {
	// Absent without a CloudInvestigator.
	if _, ok := findCloudTool(BuildCatalog(Deps{}), "investigate_cloud"); ok {
		t.Error("investigate_cloud must NOT be exposed without a CloudInvestigator (no dead tool)")
	}

	// Present + cap still satisfied when wired.
	var gotFocus string
	d := Deps{CloudInvestigator: func(_ context.Context, focus string) (string, error) {
		gotFocus = focus
		return "proven path: internet → public bucket → prod-db", nil
	}}
	c := BuildCatalog(d)
	tool, ok := findCloudTool(c, "investigate_cloud")
	if !ok {
		t.Fatal("investigate_cloud should be exposed when a CloudInvestigator is wired")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("catalog must still satisfy the ≤12 cap with the cloud tool added: %v", err)
	}

	// The handler delegates to the injected closure (the platform→specialist seam).
	res, err := tool.Handler(context.Background(), map[string]any{"focus": "paths to the prod database"}, &State{})
	if err != nil || res.Err {
		t.Fatalf("handler errored: err=%v res.Err=%v content=%q", err, res.Err, res.Content)
	}
	if gotFocus != "paths to the prod database" {
		t.Errorf("focus not threaded to the closure: %q", gotFocus)
	}
	if res.Content != "proven path: internet → public bucket → prod-db" {
		t.Errorf("specialist output not returned: %q", res.Content)
	}
}
