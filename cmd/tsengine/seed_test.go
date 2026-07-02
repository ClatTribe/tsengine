package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestSeedRoutesFromScan is the recon→offensive-agent handoff: web-investigate --scan seeds the agent
// from a prior L1 scan's discovered surface + finding endpoints, so it doesn't start blind. Asserts
// the union is returned, deduped, blanks dropped.
func TestSeedRoutesFromScan(t *testing.T) {
	scan := types.Scan{
		DiscoveredSurface: []string{
			"http://t/", "http://t/jobs", "http://t/admin", "http://t/jobs", // dup
		},
		FindingsRaw: []types.Finding{
			{Endpoint: "http://t/login"},
			{Endpoint: "http://t/jobs"}, // dup of a surface entry
			{Endpoint: ""},              // blank — must be dropped
		},
		FindingsEnriched: []types.Finding{
			{Endpoint: "http://t/api/v1/users"},
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerabilities.json")
	data, _ := json.Marshal(scan)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := seedRoutesFromScan(path)
	if err != nil {
		t.Fatalf("seedRoutesFromScan: %v", err)
	}
	want := map[string]bool{
		"http://t/": true, "http://t/jobs": true, "http://t/admin": true,
		"http://t/login": true, "http://t/api/v1/users": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d routes %v, want %d distinct", len(got), got, len(want))
	}
	for _, r := range got {
		if !want[r] {
			t.Errorf("unexpected route %q", r)
		}
		if r == "" {
			t.Error("blank route leaked through")
		}
	}
}

// TestSeedRoutesFromScan_Missing: a bad path is an error the caller surfaces, not a silent empty seed.
func TestSeedRoutesFromScan_Missing(t *testing.T) {
	if _, err := seedRoutesFromScan(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("want error for a missing scan report, got nil")
	}
}
