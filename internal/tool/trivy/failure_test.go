package trivy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// fakeOnPath installs an executable named `name` that runs `script`, and puts it first on PATH.
func fakeOnPath(t *testing.T, name, script string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestRun_FatalExitIsNotACleanScan is the regression test for the defect that motivated
// tool.Failed. It reproduces the measured failure exactly:
//
//	TRIVY_DB_REPOSITORY="::::invalid" trivy fs --format json --quiet .
//	→ exit 1 · 0 bytes on stdout · FATAL on stderr
//
// Before the fix this wrapper returned (Result{Findings: nil}, nil) — a scanner that could not reach
// its vulnerability database reported a CLEAN SCAN. Downstream that pass stayed authoritative, so
// detect.Reconcile resolved incidents, retest.Verify confirmed fixes, and grc.Reconcile flipped
// control gaps to MET on the strength of a scan that never happened.
func TestRun_FatalExitIsNotACleanScan(t *testing.T) {
	fakeOnPath(t, "trivy", `echo '2026-08-24 FATAL failed to download vulnerability DB' >&2; exit 1`)

	res, err := (&Trivy{}).Run(context.Background(), tool.Args{"mode": "fs", "target": "."})
	if err == nil {
		t.Fatalf("a fatal trivy exit returned err=nil with %d findings — this is the silent clean "+
			"scan: nothing downstream can tell it apart from a genuinely clean repository", len(res.Findings))
	}
	if !strings.Contains(err.Error(), "vulnerability DB") {
		t.Errorf("the failure reason does not name the cause: %q. This string reaches an operator "+
			"through Scan.ToolsFailed, and \"exit status 1\" is the same message for every distinct "+
			"way a scanner can fail.", err)
	}
}

// TestRun_MissingBinaryStillFails guards the case tool.DidNotRun already covered, so a future
// refactor of Failed cannot regress it: a sandbox image built without this tool must not scan clean.
func TestRun_MissingBinaryStillFails(t *testing.T) {
	fakeOnPath(t, "trivy", `exit 127`)
	if _, err := (&Trivy{}).Run(context.Background(), tool.Args{"mode": "fs", "target": "."}); err == nil {
		t.Error("a tool that never ran returned a clean result")
	}
}

// TestRun_SuccessfulEmptyScanIsStillClean is the mirror, and it is why the fix is a per-call-site
// declaration rather than a blanket rule. A repository with no vulnerabilities must keep returning
// no findings and NO error — otherwise the fix trades a false all-clear for a permanently degraded
// pass, in which incidents never resolve and no fix is ever confirmed.
func TestRun_SuccessfulEmptyScanIsStillClean(t *testing.T) {
	fakeOnPath(t, "trivy", `echo '{"Results":[]}'; exit 0`)
	res, err := (&Trivy{}).Run(context.Background(), tool.Args{"mode": "fs", "target": "."})
	if err != nil {
		t.Fatalf("a clean scan was reported as a failure: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("clean scan produced %d findings", len(res.Findings))
	}
}
