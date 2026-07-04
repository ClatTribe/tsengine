package cloudgraph

import (
	"path/filepath"
	"testing"
)

func TestLoadSnapshot_SampleInventory(t *testing.T) {
	snap, err := LoadSnapshot(filepath.Join("..", "..", "fixtures", "cloud", "sample-inventory.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if snap.AccountID != "111122223333" || snap.Provider != "aws" {
		t.Errorf("metadata mis-parsed: %s %s", snap.AccountID, snap.Provider)
	}
	if snap.Node("bucket-pii") == nil || snap.Node("bucket-pii").Sensitive != SensHigh {
		t.Error("bucket-pii should be a high-sensitivity node")
	}
	// the ingested graph must contain the internet→PII kill-chain
	paths := snap.FindPaths(InternetID, SensitiveData, AllAttackEdges, 8, 50)
	if len(paths) != 1 {
		t.Fatalf("want 1 attack path from the ingested inventory, got %d", len(paths))
	}
	if got := paths[0].Nodes[len(paths[0].Nodes)-1]; got != "bucket-pii" {
		t.Errorf("path should end at bucket-pii, got %q", got)
	}
}

// TestToInventory_PrivescConditionSurvivesRoundTrip: a CONDITION-GATED privesc edge (the #827 flag — a
// config-possible-only escalation, e.g. iam:CreateAccessKey requires MFA) must survive ToInventory→Ingest.
// InvPrivesc lacked a Condition field (unlike InvTrust/InvGrant/InvReach/InvTrigger/InvSecretAccess), so
// ToInventory silently DROPPED it: the round-tripped edge came back unconditional → Path.Conditional()
// read a path through it as DEFINITE, re-introducing exactly the over-certainty #827 fixed — at the
// serialization boundary (EmitScenario → scan --snapshot re-ingest). §10: a conditional escalation must
// never be reported as definite.
func TestToInventory_PrivescConditionSurvivesRoundTrip(t *testing.T) {
	const cond = "iam-condition-gated escalation (config-possible; validate live)"
	s1 := New("acct", "aws")
	s1.AddNode(&Node{ID: InternetID, Kind: KindNetwork, Name: "internet"}) // Ingest always injects this; add it so the Hash round-trip is symmetric
	s1.AddNode(&Node{ID: "role", Kind: KindPrincipal, Name: "role"})
	s1.AddNode(&Node{ID: AdminID, Kind: KindPrincipal, Name: "effective-admin", Privileged: true})
	s1.AddEdge(Edge{From: "role", To: AdminID, Kind: EdgePrivesc, Detail: "CreateAccessKey", Condition: cond})

	s2 := Ingest(s1.ToInventory())

	var found bool
	for _, e := range s2.Edges {
		if e.Kind == EdgePrivesc && e.From == "role" && e.To == AdminID {
			found = true
			if e.Condition != cond {
				t.Errorf("privesc condition lost in round-trip: want %q, got %q", cond, e.Condition)
			}
		}
	}
	if !found {
		t.Fatal("privesc edge missing after round-trip")
	}
	if s1.Hash() != s2.Hash() {
		t.Errorf("round-trip changed the graph (condition dropped):\n %s\n %s", s1.Hash(), s2.Hash())
	}
}

func TestParseInventory_RoundTrip(t *testing.T) {
	in := `{"account_id":"a","provider":"aws","resources":[{"id":"r1","kind":"resource"}],
	  "trusts":[{"principal":"p","role":"q","condition":"mfa"}]}`
	inv, err := ParseInventory([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if inv.AccountID != "a" || len(inv.Resources) != 1 || inv.Resources[0].ID != "r1" {
		t.Errorf("resources mis-parsed: %+v", inv)
	}
	if len(inv.Trusts) != 1 || inv.Trusts[0].Condition != "mfa" {
		t.Errorf("trusts mis-parsed: %+v", inv.Trusts)
	}
}
