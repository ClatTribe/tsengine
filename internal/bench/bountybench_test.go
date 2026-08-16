package bench

import (
	"os"
	"path/filepath"
	"testing"
)

func writeBounty(t *testing.T, root, project, bounty, metadata string, withVerify, withExploit bool) {
	t.Helper()
	base := filepath.Join(root, project, "bounties", bounty)
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "bounty_metadata.json"), []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	if withVerify {
		d := filepath.Join(base, "verify_files")
		_ = os.MkdirAll(d, 0o755)
		_ = os.WriteFile(filepath.Join(d, "verify.sh"), []byte("#!/bin/sh\n"), 0o600)
	}
	if withExploit {
		d := filepath.Join(base, "exploit_files")
		_ = os.MkdirAll(d, 0o755)
		_ = os.WriteFile(filepath.Join(d, "exploit.sh"), []byte("#!/bin/sh\n"), 0o600)
	}
}

func TestLoadBountyBench_ParsesRealLayout(t *testing.T) {
	root := t.TempDir()
	writeBounty(t, root, "lunary", "bounty_0", `{
      "CWE":"CWE-639: Authorization Bypass Through User-Controlled Key",
      "CVE":"CVE-2024-1625","severity":"7.5",
      "disclosure_bounty":"1080","patch_bounty":"225",
      "patch":{"patch_files/index.ts":"codebase/src/index.ts"}}`, true, true)
	// A bounty with no oracle: gradable only for patch, and never counted as verifiable.
	writeBounty(t, root, "django", "bounty_1", `{"CWE":"CWE-89: SQL Injection","severity":"9.8",
      "patch_bounty":"500","patch":{"a":"b"}}`, false, false)

	tasks, err := LoadBountyBench(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("want 2 tasks, got %d", len(tasks))
	}
	d := tasks[0] // sorted: django before lunary
	if d.Project != "django" || d.CWEID() != "CWE-89" || d.PatchUSD != 500 {
		t.Errorf("django task mis-parsed: %+v", d)
	}
	if d.HasVerify || d.HasExploit {
		t.Error("a bounty with no verify.sh/exploit.sh must not claim to have them — a missing " +
			"oracle is a task we cannot grade, never one we passed")
	}
	l := tasks[1]
	if l.CWEID() != "CWE-639" || l.CVE != "CVE-2024-1625" || l.Severity != 7.5 || !l.HasVerify {
		t.Errorf("lunary task mis-parsed: %+v", l)
	}
}

// The inventory must count coverage only where a real capability exists. CWE-639 is covered
// (bola_probe + apiauthz); an invented class must not be.
func TestInventoryBountyBench_CoverageIsGrounded(t *testing.T) {
	inv := InventoryBountyBench([]BountyTask{
		{Project: "a", CWE: "CWE-639: BOLA", HasPatch: true, HasVerify: true, PatchUSD: 225},
		{Project: "a", CWE: "CWE-89: SQLi", HasPatch: true},
		{Project: "b", CWE: "CWE-1333: ReDoS", HasPatch: true}, // no detector for this
	})
	if inv.Covered != 2 || inv.Uncovered != 1 {
		t.Errorf("covered/uncovered = %d/%d, want 2/1 — CWE-1333 has no detector and must not "+
			"be counted as covered", inv.Covered, inv.Uncovered)
	}
	if len(inv.UncoveredCWEs) != 1 || inv.UncoveredCWEs[0] != "CWE-1333" {
		t.Errorf("the uncovered class must be named as backlog: %v", inv.UncoveredCWEs)
	}
	if inv.Projects != 2 || inv.PatchTasks != 3 || inv.VerifyTasks != 1 {
		t.Errorf("inventory counts wrong: %+v", inv)
	}
	if inv.TotalPatchUSD != 225 {
		t.Errorf("patch bounty total = %d, want 225", inv.TotalPatchUSD)
	}
}

// TestCWEID_HandlesTheirRealFormats pins parsing against the shapes actually present in their corpus.
func TestCWEID_HandlesTheirRealFormats(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"CWE-639: Authorization Bypass Through User-Controlled Key", "CWE-639"},
		{`CWE-29: Path Traversal: '\..\filename'`, "CWE-29"}, // two colons
		{"400", "CWE-400"}, // bare number
		{"  CWE-22  ", "CWE-22"},
		{"", ""},
	} {
		if got := (BountyTask{CWE: tc.in}).CWEID(); got != tc.want {
			t.Errorf("CWEID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Sibling CWEs describing the same bug must not read as uncovered.
//
// Their corpus labels path traversal CWE-22, CWE-23 and CWE-29 — 5 of 46 bounties use the variants.
// Counting those as separate classes UNDERSTATED coverage by 7 tasks (14 → 21 once collapsed). This
// is the same trap the SAST scorer hit when semgrep emitted CWE-326 for crypto cases labelled
// CWE-327 and every real detection was discarded.
func TestInventoryBountyBench_CollapsesSiblingCWEs(t *testing.T) {
	inv := InventoryBountyBench([]BountyTask{
		{Project: "a", CWE: "CWE-22: Path Traversal"},
		{Project: "a", CWE: "CWE-23: Relative Path Traversal"},
		{Project: "a", CWE: `CWE-29: Path Traversal: '\..\filename'`},
		{Project: "a", CWE: "CWE-776: XML Entity Expansion"}, // sibling of CWE-611
	})
	if inv.Covered != 4 || inv.Uncovered != 0 {
		t.Errorf("covered/uncovered = %d/%d, want 4/0 — CWE-23/29 are path traversal and CWE-776 "+
			"is XXE; a detector for the family covers the variants", inv.Covered, inv.Uncovered)
	}
}

// Collapsing must not over-reach: an unrelated class stays uncovered.
func TestInventoryBountyBench_DoesNotOverCollapse(t *testing.T) {
	inv := InventoryBountyBench([]BountyTask{{Project: "a", CWE: "CWE-400: Denial of Service"}})
	if inv.Covered != 0 {
		t.Error("CWE-400 (DoS) has no detector here and must not be absorbed into a covered family")
	}
}
