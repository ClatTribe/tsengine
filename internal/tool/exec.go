package tool

import (
	"errors"
	"os/exec"
	"strings"
)

// DidNotRun reports whether err means the command never actually executed, as
// opposed to running and exiting non-zero.
//
// The distinction is the whole point, and every wrapper in this package used to
// miss it. Scanners routinely exit non-zero to MEAN something — semgrep exits 1
// when it finds issues, naabu when it finds no open ports — so a wrapper that
// treats every non-zero exit as a failure loses real findings.
//
// THIS COMMENT USED TO NAME TRIVY IN THAT LIST AND IT WAS WRONG, which is the
// belief that produced the silent-clean-scan defect. trivy exits 1 on findings
// only when given --exit-code, and we do not pass it; the same is true of grype
// and --fail-on. For our invocations a non-zero exit from either is ALWAYS an
// error. See Failed below — the exit semantics belong to the CALL SITE and its
// flags, not to the tool in the abstract. The uniform
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

// Failed reports that the tool RAN and exited in a way that is not one of its declared
// findings-signals — that is, it errored, and its output must not be read as a result.
//
// # The defect this exists to close, measured
//
// DidNotRun above draws the right distinction and its own doc names trivy as a tool that "exits 1
// when it finds issues". WITH OUR FLAGS THAT IS FALSE. We pass no --exit-code to trivy and no
// --fail-on to grype, so those tools exit 0 on findings and non-zero ONLY on error. Every wrapper
// nonetheless swallowed the non-zero exit and parsed whatever came out.
//
// Measured, against a real trivy 0.70:
//
//	TRIVY_DB_REPOSITORY="::::invalid" trivy fs --format json --quiet .
//	→ exit 1 · stdout 0 bytes · FATAL on stderr
//
// and through our wrapper: err=nil, findings=0. An unreachable vulnerability database — the single
// most likely real-world failure for a scanner that fetches its DB on every scan — was reported to
// the platform as a SUCCESSFUL CLEAN SCAN. Downstream, ToolsFailed stayed empty, the pass stayed
// authoritative, and detect.Reconcile resolved incidents, retest.Verify confirmed fixes and
// grc.Reconcile flipped control gaps to MET. The three degraded-mode guards built to prevent exactly
// that cascade were bypassed, because the failure never became a failure.
//
// # Why the fix is a declaration and not a rule
//
// "Any non-zero exit is a failure" is right for trivy and grype and WRONG for semgrep, gitleaks and
// hadolint, which exit 1 to mean "I found things". Applying either rule uniformly breaks half the
// wrappers — one direction loses findings, the other reports failure on every successful scan and
// degrades the pass forever. So each wrapper DECLARES the exit codes its own invocation uses as a
// findings signal, and everything else is an error:
//
//	tool.Failed(err)      // no declared findings-exit: any non-zero is an error (trivy, grype)
//	tool.Failed(err, 1)   // exit 1 means findings (semgrep-style invocations)
//
// The declaration belongs at the call site because it depends on the FLAGS that call site passes,
// not on the tool in the abstract — which is precisely what the old comment got wrong about trivy.
func Failed(err error, findingExits ...int) bool {
	if err == nil {
		return false
	}
	if DidNotRun(err) {
		return true // never ran; its silence proves nothing
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return true
	}
	code := ee.ExitCode()
	for _, ok := range findingExits {
		if code == ok {
			return false // the scanner talking, not failing
		}
	}
	return true
}

// stderrTailBytes is how much of a failed tool's stderr rides along in the error. Enough for the
// FATAL line scanners lead with, short enough that a failure list stays readable.
const stderrTailBytes = 400

// ExitDetail renders a failed exec as something an operator can act on.
//
// The failure reason reaches a human through Scan.ToolsFailed and the degraded-pass banner, and
// "exit status 1" names no cause at all — every distinct failure a scanner has looks identical.
// cmd.Output() already captures stderr into the ExitError and every wrapper threw it away, so the
// one line that says WHY ("FATAL failed to download vulnerability DB") was collected and discarded.
//
// NOTE THE PRECONDITION: only cmd.Output() populates ExitError.Stderr. A wrapper that runs its tool
// with cmd.Run() or a hand-wired StderrPipe gets the bare "exit status 1" back from here, correctly
// — there is nothing to recover — but it also gets no cause, so prefer Output in wrappers.
func ExitDetail(err error) string {
	if err == nil {
		return ""
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || len(ee.Stderr) == 0 {
		return err.Error()
	}
	msg := strings.TrimSpace(string(ee.Stderr))
	if len(msg) > stderrTailBytes {
		// The tail, not the head: scanners print progress first and the fatal line last.
		msg = "…" + msg[len(msg)-stderrTailBytes:]
	}
	return err.Error() + ": " + strings.ReplaceAll(msg, "\n", " · ")
}
