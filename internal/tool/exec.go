package tool

import (
	"errors"
	"os/exec"
)

// DidNotRun reports whether err means the command never actually executed, as
// opposed to running and exiting non-zero.
//
// The distinction is the whole point, and every wrapper in this package used to
// miss it. Scanners routinely exit non-zero to MEAN something — semgrep and trivy
// exit 1 when they find issues, naabu when it finds no open ports — so a wrapper
// that treats every non-zero exit as a failure loses real findings. The uniform
// response was to swallow every *exec.ExitError and parse whatever came out.
//
// That collapses two facts §10 keeps apart: "the tool looked and found nothing"
// and "the tool never looked". A sandbox image built without an asset's toolset
// stubs the missing binary to exit 127, so an ip-asset scan in an image built
// without ip tools ran naabu, got nothing, and reported a completed scan with
// tools_failed=0 and zero findings — while the port was wide open and nmap, in
// the same image, could see it. A benchmark scored that as a capability result.
//
// So: a missing binary (*exec.Error, never found in PATH), a shell reporting
// command-not-found (127) or not-executable (126), and a process killed by a
// signal all mean the tool did not run and its silence proves nothing. Every
// other non-zero exit is the scanner talking, and is left alone.
func DidNotRun(err error) bool {
	if err == nil {
		return false
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		// *exec.Error (binary not in PATH), context deadline, pipe failure —
		// nothing here is the scanner reporting a result.
		return true
	}
	switch ee.ExitCode() {
	case 126, 127:
		// 126 not executable, 127 command not found. No scanner uses these to
		// signal a finding; both mean the shell could not start the thing.
		return true
	case -1:
		// Killed by a signal (SIGKILL from an OOM, SIGSEGV). Whatever it had
		// written is a fragment, and its silence is not evidence of a clean target.
		return true
	}
	return false
}
