package tool

import (
	"errors"
	"os/exec"
	"testing"
)

// TestFailed_UndeclaredNonZeroExitIsAFailure is the unit-level statement of the silent-clean-scan
// defect: for a call site that declares NO findings-exit, any non-zero exit must be a failure.
func TestFailed_UndeclaredNonZeroExitIsAFailure(t *testing.T) {
	err := exec.Command("sh", "-c", "echo FATAL >&2; exit 1").Run()
	if err == nil {
		t.Fatal("the fixture did not fail, so this test proves nothing")
	}
	if !Failed(err) {
		t.Error("exit 1 with no declared findings-exit was not reported as a failure. This is the " +
			"trivy/grype path: the tool errored, produced no report, and the scan was recorded clean.")
	}
	if Failed(err, 1) {
		t.Error("exit 1 was reported as a failure even though the call site DECLARED 1 as its " +
			"findings-exit. That direction breaks semgrep-shaped tools — every successful scan that " +
			"found something would degrade the pass.")
	}
	if !Failed(err, 2, 3) {
		// only an EXACT match may clear it — a near-miss is still a failure
		t.Error("exit 1 was cleared against declared exits {2,3}")
	}
}

func TestFailed_NeverRanIsAlwaysAFailure(t *testing.T) {
	err := exec.Command("tsengine-no-such-binary-anywhere").Run()
	if err == nil {
		t.Fatal("fixture ran a binary that should not exist")
	}
	// Even if a call site declares every exit code as a findings-signal, a tool that never ran has
	// found nothing and proven nothing.
	if !Failed(err, 0, 1, 2, 127) {
		t.Error("a binary that does not exist was cleared as a findings-signal")
	}
}

func TestFailed_NilIsNotAFailure(t *testing.T) {
	if Failed(nil) {
		t.Error("a successful run was reported as a failure")
	}
}

// TestExitDetail_CarriesTheCause pins the operator-facing half. "exit status 1" is the same string
// for a bad credential, an unreadable target and an unreachable vulnerability DB.
func TestExitDetail_CarriesTheCause(t *testing.T) {
	// .Output(), NOT .Run(): only Output captures stderr into the ExitError, which is what makes the
	// cause recoverable at all. Both wrappers this protects use Output — a wrapper that switched to
	// Run would silently lose the reason again, so the fixture uses the same call they do.
	_, err := exec.Command("sh", "-c", "echo 'FATAL failed to download vulnerability DB' >&2; exit 1").Output()
	got := ExitDetail(err)
	if !contains(got, "vulnerability DB") {
		t.Errorf("ExitDetail lost the reason: %q — the stderr line naming the cause is captured by "+
			"cmd.Output() and was being discarded", got)
	}
	if !contains(got, "exit status 1") {
		t.Errorf("ExitDetail dropped the exit status: %q", got)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatal("fixture produced no ExitError")
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
