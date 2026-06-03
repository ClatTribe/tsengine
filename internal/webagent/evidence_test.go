package webagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// richTarget plants five distinct real vulns + a naive WAF, exercising every
// indicator class the engine grounds on.
func richTarget() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/product", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, "'\"") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Database error: You have an error in your SQL syntax near '%s'", id)
			return
		}
		fmt.Fprintf(w, "<h1>Product %s</h1>", id)
	})
	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if strings.Contains(strings.ToLower(name), "<script") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "blocked by WAF")
			return
		}
		fmt.Fprintf(w, "<div>Hello, %s!</div>", name)
	})
	mux.HandleFunc("/out", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		if strings.Contains(f, "..") { // path traversal → leak /etc/passwd
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
			return
		}
		fmt.Fprintf(w, "file: %s", f)
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if strings.ContainsAny(host, ";|&") { // command injection → run `id`
			fmt.Fprint(w, "PING 127.0.0.1: 56 data bytes\nuid=0(root) gid=0(root) groups=0(root)\n")
			return
		}
		fmt.Fprintf(w, "PING %s ok", host)
	})
	return httptest.NewServer(mux)
}

func newFullPlaybook(base string) *playbookBrain {
	return &playbookBrain{
		lastIdx: -1,
		probes: []probe{
			{q(base, "/product", "id", "'"), "'", "sqli", "sql_error"},
			{q(base, "/greet", "name", "<script>alert(1)</script>"), "<script>alert(1)</script>", "xss", "reflected_input"},             // blocked
			{q(base, "/greet", "name", "\"><img src=x onerror=alert(1)>"), "\"><img src=x onerror=alert(1)>", "xss", "reflected_input"}, // bypass
			{q(base, "/out", "next", "http://evil.test/"), "http://evil.test/", "open_redirect", "external_redirect"},
			{q(base, "/download", "file", "../../../../etc/passwd"), "", "path_traversal", "file_disclosure"},
			{q(base, "/ping", "host", "127.0.0.1;id"), "", "command_injection", "cmd_output"},
		},
	}
}

// TestE2E_FiveClasses_SignedEvidence is the full end-to-end proof: the real loop
// discovers all five classes on a live target via indicators, then we produce a
// signed evidence bundle and verify it — and a tampered bundle is rejected.
func TestE2E_FiveClasses_SignedEvidence(t *testing.T) {
	srv := richTarget()
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	rep, err := Investigate(context.Background(), newFullPlaybook(srv.URL), cc, Options{MaxRequests: 80, MaxIters: 50})
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	key := map[string]string{
		q(srv.URL, "/product", "id", "'"):                               "sqli",
		q(srv.URL, "/greet", "name", "\"><img src=x onerror=alert(1)>"): "xss",
		q(srv.URL, "/out", "next", "http://evil.test/"):                 "open_redirect",
		q(srv.URL, "/download", "file", "../../../../etc/passwd"):       "path_traversal",
		q(srv.URL, "/ping", "host", "127.0.0.1;id"):                     "command_injection",
	}
	sc := rep.ScoreAgainst(key)
	t.Log("\n" + Render(rep))
	t.Logf("score: recall=%.0f%% (%d/%d) invented=%d pass=%v", sc.Recall*100, sc.RealFound, sc.RealTotal, sc.Invented, sc.Pass)
	if !sc.Pass {
		t.Fatalf("want all 5 classes, 0 invented; got %+v missed=%v", sc, sc.Missed)
	}
	for _, f := range rep.Findings {
		if !f.Verified {
			t.Errorf("finding %s (%s) not Verified", f.ID, f.Class)
		}
	}

	// --- signed evidence bundle ---
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	bundle := BuildEvidence(rep, cc, "tsengine test")
	if len(bundle.Findings) != 5 {
		t.Fatalf("bundle has %d findings, want 5", len(bundle.Findings))
	}
	// every finding carries its proving request+response
	for _, ef := range bundle.Findings {
		if len(ef.ProvingTurns) == 0 {
			t.Errorf("%s has no proving turns", ef.ID)
			continue
		}
		if ef.ProvingTurns[0].RespSnippet == "" {
			t.Errorf("%s proving turn has no captured response", ef.ID)
		}
	}
	if err := SignEvidence(bundle, "tsengine-test-key", priv, now); err != nil {
		t.Fatalf("sign: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	if err := ExportEvidence(path, bundle); err != nil {
		t.Fatalf("export: %v", err)
	}
	loaded, err := LoadEvidence(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := VerifyEvidence(loaded, pub); err != nil {
		t.Fatalf("verify (untampered) should pass: %v", err)
	}

	// tamper: flip a finding's class on disk → verification MUST fail
	tampered, _ := LoadEvidence(path)
	tampered.Findings[0].Class = "rce"
	if err := VerifyEvidence(tampered, pub); err == nil {
		t.Fatalf("tampered bundle verified — attestation is not tamper-evident")
	} else {
		t.Logf("tamper correctly rejected: %v", err)
	}

	// optional: persist for a CLI web-verify demo (set TSENGINE_EVIDENCE_OUT)
	if out := os.Getenv("TSENGINE_EVIDENCE_OUT"); out != "" {
		if err := ExportEvidence(out, bundle); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(out+".pub", []byte(hex.EncodeToString(pub)), 0o600)
		t.Logf("persisted bundle → %s (pubkey → %s.pub)", out, out)
	}
}

// TestSeedFindings_Surfaced confirms L1 seed findings reach the agent's working
// state and prompt (so it confirms them instead of rediscovering).
func TestSeedFindings_Surfaced(t *testing.T) {
	srv := richTarget()
	defer srv.Close()

	seeds := []SeedFinding{
		{Route: srv.URL + "/product?id=", Class: "sqli", Tool: "sqlmap"},
		{Route: srv.URL + "/download?file=", Class: "path_traversal", Tool: "nuclei"},
	}
	// finish immediately; we only assert seeds are wired in.
	brain := &scriptLLM{steps: []string{`{"tool":"finish","args":{"summary":"noop"}}`}}
	cc := &Context{Target: srv.URL}
	if _, err := Investigate(context.Background(), brain, cc, Options{SeedFindings: seeds, MaxRequests: 5}); err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	if len(cc.Seeds) != 2 {
		t.Fatalf("seeds not stored on context: %+v", cc.Seeds)
	}
	prompt := buildPrompt(cc, nil)
	if !strings.Contains(prompt, "SUSPECTED FINDINGS FROM L1 SCANNERS") ||
		!strings.Contains(prompt, "sqlmap") || !strings.Contains(prompt, "path_traversal on") {
		t.Errorf("seed findings not surfaced in the prompt")
	}
}
