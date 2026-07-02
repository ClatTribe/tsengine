package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestSeedRoutesFromScan is the recon→offensive-agent handoff, using the REAL formats a live scan
// produces: the surface hosts are the sandbox-rewritten host.docker.internal (the agent runs host-side
// against localhost, so they MUST be re-hosted or the allowlist blocks them — the bug the XBEN-006
// live run exposed), plus "SPEC <url>" markers and "POST /path" finding endpoints. All must normalize
// onto the target base, deduped.
func TestSeedRoutesFromScan(t *testing.T) {
	scan := types.Scan{
		DiscoveredSurface: []string{
			"SPEC http://host.docker.internal:8000/openapi.json", // spec marker → plain URL, re-hosted
			"http://host.docker.internal:8000",                   // sandbox host → target host
			"http://host.docker.internal:8000/jobs",              // the injection point, wrong host
			"http://host.docker.internal:8000/jobs",              // dup
		},
		FindingsRaw: []types.Finding{
			{Endpoint: "POST /jobs"},                              // method-prefixed bare path
			{Endpoint: "http://host.docker.internal:8000/ping"},   // full URL, sandbox host
			{Endpoint: ""},                                        // blank — dropped
		},
		FindingsEnriched: []types.Finding{
			{Endpoint: "/admin"}, // bare path
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerabilities.json")
	data, _ := json.Marshal(scan)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := seedRoutesFromScan(path, "http://localhost:8000")
	if err != nil {
		t.Fatalf("seedRoutesFromScan: %v", err)
	}
	want := map[string]bool{
		"http://localhost:8000/openapi.json": true,
		"http://localhost:8000/":             true, // bare host → RequestURI "/"
		"http://localhost:8000/jobs":         true,
		"http://localhost:8000/ping":         true,
		"http://localhost:8000/admin":        true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d routes %v, want %d distinct", len(got), got, len(want))
	}
	for _, r := range got {
		if !want[r] {
			t.Errorf("route %q not normalized onto the target host (would be blocked by the agent allowlist)", r)
		}
	}
}

// TestSeedRoutesFromScan_Missing: a bad path is an error the caller surfaces, not a silent empty seed.
func TestSeedRoutesFromScan_Missing(t *testing.T) {
	if _, err := seedRoutesFromScan(filepath.Join(t.TempDir(), "nope.json"), "http://localhost:8000"); err == nil {
		t.Error("want error for a missing scan report, got nil")
	}
}
