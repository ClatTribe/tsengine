package cloudgraph

import "testing"

func invWithCopy(srcSens Sensitivity, copyPublic bool) Inventory {
	return Inventory{
		AccountID: "1", Provider: "aws",
		Resources: []InvResource{
			{ID: "db-prod", Kind: KindData, Type: "rds_instance", Sensitive: srcSens},
			{ID: "snap-2024", Kind: KindData, Type: "rds_snapshot", Public: copyPublic},
		},
		Copies: []InvCopy{{Copy: "snap-2024", Source: "db-prod", Detail: "rds snapshot"}},
	}
}

// THE ONE THAT MATTERS: the classic breach. A locked-down sensitive primary, and a PUBLIC snapshot of it
// that nobody classified. Without inheritance the snapshot reads as an unremarkable public bucket and
// the DSPM check (public AND sensitive) never fires.
func TestCopies_SnapshotInheritsSourceSensitivity(t *testing.T) {
	snap := Ingest(invWithCopy(SensHigh, true))
	n := snap.Node("snap-2024")
	if n == nil {
		t.Fatal("snapshot node missing")
	}
	if n.Sensitive != SensHigh {
		t.Errorf("public snapshot of a HIGH-sensitivity database has Sensitive=%q — the copy holds the "+
			"same data as its source, and unclassified it looks like an ordinary public bucket", n.Sensitive)
	}
}

// Inheritance is transitive: a snapshot of a replica of a sensitive database is sensitive.
func TestCopies_InheritanceIsTransitive(t *testing.T) {
	inv := Inventory{
		AccountID: "1", Provider: "aws",
		Resources: []InvResource{
			{ID: "db", Kind: KindData, Sensitive: SensHigh},
			{ID: "replica", Kind: KindData},
			{ID: "snap", Kind: KindData, Public: true},
		},
		Copies: []InvCopy{
			{Copy: "snap", Source: "replica", Detail: "snapshot of replica"},
			{Copy: "replica", Source: "db", Detail: "read replica"},
		},
	}
	if got := Ingest(inv).Node("snap").Sensitive; got != SensHigh {
		t.Errorf("a snapshot of a replica of a sensitive DB has Sensitive=%q, want high — the data is the "+
			"same however many hops it was copied", got)
	}
}

// It must never DOWNGRADE. A copy already classified higher than its source keeps its own rating.
func TestCopies_NeverDowngrades(t *testing.T) {
	inv := Inventory{
		AccountID: "1", Provider: "aws",
		Resources: []InvResource{
			{ID: "src", Kind: KindData, Sensitive: SensLow},
			{ID: "cp", Kind: KindData, Sensitive: SensHigh},
		},
		Copies: []InvCopy{{Copy: "cp", Source: "src"}},
	}
	if got := Ingest(inv).Node("cp").Sensitive; got != SensHigh {
		t.Errorf("inheritance downgraded a copy from high to %q — propagation may only ever raise", got)
	}
}

// Grounded: a non-sensitive source gives nothing away, and a copy of a resource we never saw asserts
// nothing rather than erroring.
func TestCopies_NoPhantomSensitivity(t *testing.T) {
	if got := Ingest(invWithCopy(SensNone, true)).Node("snap-2024").Sensitive; got != SensNone {
		t.Errorf("a copy of an UNclassified source became %q — sensitivity was invented", got)
	}
	inv := Inventory{
		AccountID: "1", Provider: "aws",
		Resources: []InvResource{{ID: "only", Kind: KindData, Sensitive: SensHigh}},
		Copies:    []InvCopy{{Copy: "ghost", Source: "only"}, {Copy: "only", Source: "also-ghost"}},
	}
	if snap := Ingest(inv); snap.Node("ghost") != nil {
		t.Error("a copy edge created a node that was never in the inventory")
	}
}

// The lineage must be a real edge, so a human (and the path renderer) can see WHY the copy is sensitive.
func TestCopies_EdgeIsRecorded(t *testing.T) {
	snap := Ingest(invWithCopy(SensHigh, true))
	found := false
	for _, e := range snap.Edges {
		if e.Kind == EdgeCopyOf && e.From == "db-prod" && e.To == "snap-2024" {
			found = true
			if e.Detail == "" {
				t.Error("copy edge carries no detail — a reader cannot tell a snapshot from a replica")
			}
		}
	}
	if !found {
		t.Error("no copy_of edge recorded — the inheritance would be unexplainable")
	}
}

// A cycle in asserted lineage must terminate rather than hang.
func TestCopies_CycleTerminates(t *testing.T) {
	inv := Inventory{
		AccountID: "1", Provider: "aws",
		Resources: []InvResource{
			{ID: "a", Kind: KindData, Sensitive: SensHigh},
			{ID: "b", Kind: KindData},
		},
		Copies: []InvCopy{{Copy: "b", Source: "a"}, {Copy: "a", Source: "b"}},
	}
	if got := Ingest(inv).Node("b").Sensitive; got != SensHigh {
		t.Errorf("cycle broke propagation: b is %q", got)
	}
}
