package bench

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestExtractExploitFromTranscript pulls the winning request out of an offensive transcript: the turn
// whose RESPONSE carried the flag becomes the replayable exploit (path/method/body), reduced to a
// target-relative path so it replays against a rebuilt app on a different port.
func TestExtractExploitFromTranscript(t *testing.T) {
	flag := "FLAG{abc123}"
	transcript := []byte(`{"history":[
		{"method":"GET","url":"http://host:8080/","response_snippet":"home page"},
		{"method":"POST","url":"http://host:8080/login?next=/admin","body":"user=' OR 1=1-- -&pass=x","response_snippet":"welcome admin ` + flag + `"},
		{"method":"GET","url":"http://host:8080/after","response_snippet":"nothing here"}
	]}`)
	e, ok := ExtractExploitFromTranscript(transcript, flag, "XBEN-1", "sqli")
	if !ok {
		t.Fatal("should extract the flag-bearing turn as the exploit")
	}
	if len(e.Steps) != 1 {
		t.Fatalf("want 1 step, got %d", len(e.Steps))
	}
	s := e.Steps[0]
	if s.Method != "POST" || s.Path != "/login?next=/admin" || !strings.Contains(s.Body, "OR 1=1") {
		t.Errorf("extracted step wrong: %+v", s)
	}
	if e.Class != "sqli" || e.BenchmarkID != "XBEN-1" {
		t.Errorf("metadata wrong: %+v", e)
	}
	// No flag in any response → not extractable (must not fabricate an exploit).
	if _, ok := ExtractExploitFromTranscript(transcript, "FLAG{nope}", "XBEN-1", "sqli"); ok {
		t.Error("a flag that never appears must yield ok=false")
	}
}

// TestReplayExploit_AgainstVulnAndPatched: the same recorded exploit sees the flag on the vulnerable
// server and NOT on the patched one — the deterministic remediation signal.
func TestReplayExploit_AgainstVulnAndPatched(t *testing.T) {
	flag := "FLAG{xyz}"
	e := WinningExploit{BenchmarkID: "b", Steps: []ExploitStep{{Method: "POST", Path: "/login", Body: "u=' OR 1=1-- -"}}}

	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" { // the injection still works → flag leaks
			w.Write([]byte("welcome " + flag))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer vuln.Close()
	patched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(401) // the fix: injection rejected, no flag
			w.Write([]byte("invalid credentials"))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer patched.Close()

	ctx := context.Background()
	if seen, err := ReplayExploit(ctx, http.DefaultClient, vuln.URL, e, flag); err != nil || !seen {
		t.Errorf("exploit should still capture on the vuln server: seen=%v err=%v", seen, err)
	}
	if seen, err := ReplayExploit(ctx, http.DefaultClient, patched.URL, e, flag); err != nil || seen {
		t.Errorf("exploit should FAIL on the patched server: seen=%v err=%v", seen, err)
	}
}

// TestAppFunctional_RegressionGuard: the anti-sabotage guard — a live app (any <500) is functional; an app
// that 500s everything (a patch that broke it) is not.
func TestAppFunctional_RegressionGuard(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer live.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer broken.Close()
	ctx := context.Background()
	if !AppFunctional(ctx, http.DefaultClient, live.URL) {
		t.Error("a 200 homepage means the app is functional")
	}
	if AppFunctional(ctx, http.DefaultClient, broken.URL) {
		t.Error("a 500-everything app is NOT functional (a patch that broke it must not count as a fix)")
	}
}

// TestParsePatch parses the FILE-block format, rejects path traversal, and treats no-blocks as no-patch.
func TestParsePatch(t *testing.T) {
	out := "Here is the fix:\n" +
		"=== FILE: app/login.php ===\n<?php // parameterised now\n$stmt = $db->prepare('...');\n=== END FILE ===\n" +
		"and also\n" +
		"=== FILE: app/util.php ===\n<?php echo 'safe';\n=== END FILE ===\n"
	files, err := ParsePatch(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(files) != 2 || files[0].Path != "app/login.php" || !strings.Contains(files[0].Content, "parameterised") {
		t.Fatalf("parsed files wrong: %+v", files)
	}
	if files[1].Path != "app/util.php" {
		t.Errorf("second file path wrong: %q", files[1].Path)
	}
	// No blocks → no patch (nil, nil) — the engineer legitimately produced nothing, never a fabricated fix.
	if f, err := ParsePatch("I could not determine a safe fix."); err != nil || len(f) != 0 {
		t.Errorf("no-blocks must be (nil,nil), got %v / %v", f, err)
	}
	// Path traversal is rejected (a patch must not escape the build context).
	if _, err := ParsePatch("=== FILE: ../../etc/passwd ===\nx\n=== END FILE ==="); err == nil {
		t.Error("a traversal path must be rejected")
	}
	// A block with no END marker is a hard error (don't silently apply a truncated file).
	if _, err := ParsePatch("=== FILE: a.php ===\nunterminated"); err == nil {
		t.Error("an unterminated FILE block must error")
	}
}
