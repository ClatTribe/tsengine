package scoutsuite

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// stubScout puts a fake `scout` binary on PATH with directed behaviour — real process semantics,
// the same rig the §12.3 ratchet conversions use.
func stubScout(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "scout")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A non-zero exit (bad/expired credentials) must FAIL LOUDLY with its cause. Returning
// err=nil/findings=0 here is how a cloud estate nobody looked at rendered as clean — the defect
// ADR 0031 C1 ranks first.
func TestRun_AuthFailureFailsLoudly(t *testing.T) {
	stubScout(t, "#!/bin/sh\necho 'FATAL bad-creds-marker' >&2\nexit 2\n")
	res, err := New().Run(context.Background(), tool.Args{"target": "aws"})
	if err == nil {
		t.Fatalf("a failed scout run returned err=nil with %d finding(s) — the clean-on-no-creds defect", len(res.Findings))
	}
	if !strings.Contains(err.Error(), "bad-creds-marker") {
		t.Errorf("failure must carry the stderr cause: %v", err)
	}
}

// Exit 0 with no results file is equally an error — never a clean estate.
func TestRun_CleanExitNoOutputIsAnError(t *testing.T) {
	stubScout(t, "#!/bin/sh\nexit 0\n")
	if _, err := New().Run(context.Background(), tool.Args{"target": "aws"}); err == nil {
		t.Fatal("a clean exit with no results file must be an error, never a clean estate")
	}
}

// Happy path: exit 0 + a scoutsuite_results.js blob parses to findings.
func TestRun_ParsesResults(t *testing.T) {
	stubScout(t, "#!/bin/sh\n"+`mkdir -p "$5/report"
cat > "$5/report/scoutsuite_results.js" <<'EOF'
scoutsuite_results =
{"services":{"s3":{"findings":{"s3_bucket_public":{"description":"public buckets","level":"danger","flagged_items":2,"rationale":"x"}}}}}
EOF
exit 0
`)
	res, err := New().Run(context.Background(), tool.Args{"target": "aws"})
	if err != nil {
		t.Fatalf("clean run with results errored: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding from the fixture, got %d", len(res.Findings))
	}
}
