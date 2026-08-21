package tool

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The two facts DidNotRun keeps apart, exercised against REAL processes rather than
// hand-built errors — a fabricated *exec.ExitError proves the switch statement compiles,
// not that a shell reports what we think it does.
func TestDidNotRun_DistinguishesASilentToolFromAnAbsentOne(t *testing.T) {
	run := func(sh string) error {
		return exec.CommandContext(context.Background(), "sh", "-c", sh).Run()
	}

	// A scanner exiting non-zero to MEAN something. semgrep and trivy exit 1 on
	// findings; naabu exits non-zero on no open ports. Treating this as a failure
	// is how a wrapper loses real findings, which is why the swallow existed.
	if got := DidNotRun(run("exit 1")); got {
		t.Error("exit 1 is the scanner talking — a wrapper that errors here loses real findings")
	}
	if got := DidNotRun(run("exit 2")); got {
		t.Error("exit 2 likewise")
	}

	// The toolset stub: present, executable, exits 127. This is the case that
	// produced a completed scan with zero findings over a wide-open port.
	if got := DidNotRun(run("exit 127")); !got {
		t.Error("exit 127 means the shell could not start the tool — its silence proves nothing")
	}
	if got := DidNotRun(run("exit 126")); !got {
		t.Error("exit 126 means not executable — same")
	}

	// A binary that is not there at all yields *exec.Error, not *exec.ExitError.
	if got := DidNotRun(exec.CommandContext(context.Background(), "tsengine-no-such-binary-xyz").Run()); !got {
		t.Error("a binary missing from PATH did not run")
	}

	// Killed by a signal: whatever it wrote is a fragment.
	if got := DidNotRun(run("kill -9 $$")); !got {
		t.Error("a process killed by a signal did not produce a result")
	}

	// A context deadline is not the scanner reporting anything either.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if got := DidNotRun(exec.CommandContext(ctx, "sh", "-c", "sleep 5").Run()); !got {
		t.Error("a command killed by its context did not run to a result")
	}

	if DidNotRun(nil) {
		t.Error("nil is a clean run")
	}
	if !DidNotRun(errors.New("pipe failure")) {
		t.Error("a non-exec error is not a scanner exit code")
	}
}

// Every wrapper must route its exec error through DidNotRun.
//
// This is the guard, not the fix. All 36 wrappers had independently written the same
// swallow — `if !errors.As(err, &ee) { return err }`, then fall through — because it is
// the obvious way to keep a scanner's meaningful non-zero exit. The 37th will write it
// too unless something says otherwise at review time.
func TestNoWrapperSwallowsAnExitErrorWithoutClassifyingIt(t *testing.T) {
	// Scoped to the wrappers. The rule is about code that PARSES OUTPUT after a
	// non-zero exit — that is where the two facts get conflated. internal/sandbox
	// runs docker and surfaces a non-zero exit as an error already, so it has no
	// swallow to guard.
	root := "."
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil || !strings.Contains(string(src), "exec.ExitError") {
			return nil
		}
		if strings.Contains(string(src), "DidNotRun") {
			return nil // classified
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, src, 0)
		if perr != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.SelectorExpr); ok && id.Sel.Name == "ExitError" {
				offenders = append(offenders, path)
				return false
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("%d file(s) inspect *exec.ExitError without calling tool.DidNotRun: %v\n\n"+
			"Swallowing every non-zero exit makes a tool that NEVER RAN indistinguishable from one "+
			"that ran and found nothing — the §10 distinction. A sandbox image missing an asset's "+
			"toolset stubs the binary to exit 127, and that path produced a completed scan with zero "+
			"findings over a wide-open port. Route the error through tool.DidNotRun.",
			len(offenders), offenders)
	}
	fmt.Fprintf(os.Stderr, "")
}
