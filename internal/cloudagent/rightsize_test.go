package cloudagent

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func princ(id string, priv bool, attrs map[string]string) *cloudgraph.Node {
	return &cloudgraph.Node{ID: id, Kind: cloudgraph.KindPrincipal, Privileged: priv, Attrs: attrs}
}

// TestRightsizeTool: the agent's CIEM tool reports over-privilege on a dormant admin, honestly says
// "no usage data" when absent, confirms a right-sized principal, and errors on an unknown one.
func TestRightsizeTool(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(princ("dormant-admin", true, map[string]string{
		"granted_actions": "iam:* s3:GetObject", "used_actions": "", "usage_observed": "true", "usage_window_days": "90",
	}))
	s.AddNode(princ("no-data", true, map[string]string{"granted_actions": "iam:*"})) // no usage_observed
	s.AddNode(princ("tight", false, map[string]string{
		"granted_actions": "s3:GetObject", "used_actions": "s3:GetObject", "usage_observed": "true",
	}))
	cc := &Context{Snap: s}

	if out := tRightsize(cc, map[string]any{"principal": "dormant-admin"}); !strings.Contains(out, "OVER-PRIVILEGED") {
		t.Errorf("dormant admin must be flagged over-privileged: %q", out)
	}
	if out := tRightsize(cc, map[string]any{"principal": "no-data"}); !strings.Contains(out, "no usage data") {
		t.Errorf("a principal without usage data must report the honest gate: %q", out)
	}
	if out := tRightsize(cc, map[string]any{"principal": "tight"}); !strings.Contains(out, "right-sized") {
		t.Errorf("a fully-used principal must read right-sized: %q", out)
	}
	if out := tRightsize(cc, map[string]any{"principal": "ghost"}); !strings.HasPrefix(out, "ERROR") {
		t.Errorf("an unknown principal must error: %q", out)
	}
}

// TestRightsizeTool_InCatalog: the tool is registered so the LLM cloud engineer can call it.
func TestRightsizeTool_InCatalog(t *testing.T) {
	found := false
	for _, td := range tools() {
		if td.name == "rightsize_principal" {
			found = true
		}
	}
	if !found {
		t.Error("rightsize_principal must be in the cloud agent's tool catalog")
	}
	if n := len(tools()); n > 12 {
		t.Errorf("cloud agent catalog exceeds the ≤12-tool cap (§2.6): %d tools", n)
	}
}
