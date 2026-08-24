package prowler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// stubProwler puts a fake `prowler` binary on PATH that behaves as directed. This is the
// exit-contract test rig the §12.3 ratchet's other conversions use: the wrapper is exercised
// against REAL process semantics, not a mocked exec.
func stubProwler(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "prowler")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A non-zero exit (bad/expired credentials are the canonical case) must FAIL LOUDLY with the
// stderr cause — never return err=nil, findings=0. That silence is how a cloud estate nobody
// looked at rendered as clean (ADR 0031 C1, the highest confidence-at-risk defect).
func TestRun_AuthFailureFailsLoudly(t *testing.T) {
	stubProwler(t, "#!/bin/sh\necho 'CRITICAL: Unable to authenticate' >&2\nexit 1\n")
	res, err := New().Run(context.Background(), tool.Args{"target": "aws"})
	if err == nil {
		t.Fatalf("a failed prowler run returned err=nil with %d finding(s) — the clean-on-no-creds defect",
			len(res.Findings))
	}
	for _, want := range []string{"prowler", "authenticate"} {
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
			t.Errorf("failure must carry the cause (%q missing): %v", want, err)
		}
	}
	if len(res.Findings) != 0 {
		t.Errorf("a failed run must not carry findings, got %d", len(res.Findings))
	}
}

// Exit 0 but NO output file (the scanner lied / was killed after starting) is equally an error.
func TestRun_CleanExitNoOutputIsAnError(t *testing.T) {
	stubProwler(t, "#!/bin/sh\nexit 0\n")
	res, err := New().Run(context.Background(), tool.Args{"target": "aws"})
	if err == nil {
		t.Fatal("a clean exit with no OCSF output must be an error, never a clean estate")
	}
	if !strings.Contains(err.Error(), "NEVER a clean estate") {
		t.Errorf("the error must say what it means: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("no findings may ride an error result, got %d", len(res.Findings))
	}
}

// The happy path still parses: exit 0 + a real OCSF array yields findings.
func TestRun_ParsesOCSFFindings(t *testing.T) {
	stubProwler(t, "#!/bin/sh\nDIR=\"\"\nfor a in \"$@\"; do case \"$prev\" in --output-directory) DIR=$a;; esac; prev=$a; done\n"+
		"printf '%s' '[{\"status_code\":\"FAIL\",\"severity\":\"critical\",\"message\":\"bucket open\",\"finding_info\":{\"title\":\"s3 public\",\"uid\":\"p1\"},\"unmapped\":{\"check_id\":\"s3_public\"}}]' > \"$DIR/prowler.ocsf.json\"\nexit 0\n")
	res, err := New().Run(context.Background(), tool.Args{"target": "aws"})
	if err != nil {
		t.Fatalf("clean run with output errored: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding from the fixture, got %d", len(res.Findings))
	}
}
