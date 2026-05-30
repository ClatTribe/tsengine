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
