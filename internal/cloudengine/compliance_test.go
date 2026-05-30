package cloudengine

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func TestPathCompliance_SensitiveDataPath(t *testing.T) {
	snap := handBuilt() // internet → … → assume → reads PII bucket
	a := Assess(snap, nil, SnapshotOracle{}, Options{})
	if len(a.Paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(a.Paths))
	}
	c := a.Paths[0].Compliance
	if c == nil {
		t.Fatal("a public-internet → sensitive-data path must carry compliance annotations")
	}
	// internet exposure + sensitive data + cross-role assume → these controls.
	want := map[string][]string{
		"SOC2":    {"CC6.6", "CC6.1"},
		"PCI":     {"1.3", "3.4"},
		"NISTCSF": {"PR.AC-5", "PR.DS-1"},
	}
	if !containsAll(c.SOC2, want["SOC2"]) {
		t.Errorf("SOC2 = %v, want superset of %v", c.SOC2, want["SOC2"])
	}
	if !containsAll(c.PCI, want["PCI"]) {
		t.Errorf("PCI = %v, want superset of %v", c.PCI, want["PCI"])
	}
	if !containsAll(c.NISTCSF, want["NISTCSF"]) {
		t.Errorf("NIST-CSF = %v, want superset of %v", c.NISTCSF, want["NISTCSF"])
	}
}

func TestPathCompliance_PrivescMapsLeastPrivilege(t *testing.T) {
	scn := Generate(5, 0, 0, true) // privesc-to-admin only
	a := Assess(scn.Snapshot, nil, scn.Oracle(), Options{})
	if len(a.Paths) == 0 {
		t.Fatal("expected a privesc path")
	}
	c := a.Paths[0].Compliance
	if c == nil || !containsAll(c.SOC2, []string{"CC6.3"}) {
		t.Errorf("a privilege-escalation path must map to least-privilege controls (SOC2 CC6.3): %+v", c)
	}
}

func TestPathCompliance_NilWhenNoCharacteristic(t *testing.T) {
	// a path to a non-sensitive, non-privileged target with no public reach.
	if pathCompliance(cloudgraph.Path{
		Nodes: []string{"a", "b"},
		Edges: []cloudgraph.Edge{{From: "a", To: "b", Kind: cloudgraph.EdgeRunsAs}},
	}, &cloudgraph.Node{ID: "b"}) != nil {
		t.Error("a benign path should carry no compliance annotation")
	}
}

func containsAll(have, want []string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
