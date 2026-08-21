package naabu

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// The end-to-end wrapper half of tool.DidNotRun, driven through the REAL Run() against a
// REAL stub binary — not a fabricated *exec.ExitError.
//
// This is the exact production shape: docker/sandbox/toolset.sh writes a stub for every
// binary an image was not built with, and that stub exits 127. An ip-asset scan in an image
// built without ip tools therefore ran naabu, got nothing, and reported a completed scan
// with tools_failed=0 and zero findings — while the port was wide open and nmap, present in
// the same image, could see it.
//
// A unit test over the classifier proves the switch statement compiles. This proves the
// wrapper actually routes through it.
func TestRun_TreatsAMissingBinaryStubAsAFailureNotACleanScan(t *testing.T) {
	dir := t.TempDir()
	// Byte-for-byte the shape toolset.sh writes.
	stub := "#!/bin/sh\necho \"naabu is not installed in this image (built with TOOLSET=container). " +
		"Rebuild with TOOLSET=full, or add this asset to the list.\" >&2\nexit 127\n"
	if err := os.WriteFile(filepath.Join(dir, "naabu"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := New().Run(context.Background(), tool.Args{"target": "127.0.0.1"})
	if err == nil {
		t.Fatal("a stubbed-out naabu returned a clean result with no findings. That is " +
			"indistinguishable from a host with no open ports, and it is how a benchmark came " +
			"to score 0.000 against a wide-open redis while nmap saw the port fine.")
	}
	if !strings.Contains(err.Error(), "naabu") {
		t.Errorf("the error must name the tool so the failure is attributable, got %v", err)
	}
}

// The other direction, and the reason the swallow existed: naabu exits non-zero when it
// finds no open ports. That is the tool REPORTING A RESULT, and erroring on it would turn
// every clean host into a scan failure.
func TestRun_KeepsANonZeroExitThatIsTheToolTalking(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "naabu"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	res, err := New().Run(context.Background(), tool.Args{"target": "127.0.0.1"})
	if err != nil {
		t.Fatalf("exit 1 is naabu saying it found nothing — erroring here turns every clean "+
			"host into a scan failure: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("a clean host has no findings, got %d", len(res.Findings))
	}
}
