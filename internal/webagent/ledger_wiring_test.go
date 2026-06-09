package webagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/ledger"
)

// TestLedger_CapturesRealEngagement runs the REAL Investigate loop against the
// multi-vuln target with the deterministic playbook brain, while a ledger.Recorder
// captures every ReAct step. It then maps the report's grounded findings into the
// ledger's Decisions, signs it, verifies it, tampers one recorded step, and confirms
// verification breaks — the full "replayable, tamper-evident agent decision ledger"
// contract against an actual engagement (not a hand-built fixture).
func TestLedger_CapturesRealEngagement(t *testing.T) {
	srv := multiVulnTarget()
	defer srv.Close()

	rec := ledger.NewRecorder()
	cc := &Context{
		Target: srv.URL,
		Routes: []string{srv.URL + "/product?id=", srv.URL + "/greet?name=", srv.URL + "/out?next="},
	}
	rep, err := Investigate(context.Background(), newPlaybook(srv.URL), cc,
		Options{MaxRequests: 60, MaxIters: 40, Ledger: rec})
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	// The recorder must have observed the actual loop: at least one send_request and
	// one record_finding step, in that order.
	steps := rec.Steps()
	if len(steps) < 4 {
		t.Fatalf("recorder captured too few steps: %d", len(steps))
	}
	var sawSend, sawRecord bool
	var firstSend, firstRecord = -1, -1
	for i, s := range steps {
		switch s.Tool {
		case "send_request":
			sawSend = true
			if firstSend < 0 {
				firstSend = i
			}
			// the deterministic indicators the agent read must be in the observation
		case "record_finding":
			sawRecord = true
			if firstRecord < 0 {
				firstRecord = i
			}
		}
	}
	if !sawSend || !sawRecord {
		t.Fatalf("ledger missed core steps: send=%v record=%v", sawSend, sawRecord)
	}
	if firstSend > firstRecord {
		t.Errorf("a finding was recorded before any request was sent (ordering lost)")
	}

	// Map the engagement's grounded findings into ledger decisions (the CLI does the
	// same), then build + sign the ledger.
	var decisions []ledger.Decision
	for _, f := range rep.Findings {
		decisions = append(decisions, ledger.Decision{
			ID: f.ID, Kind: f.Class, Severity: f.Severity, Refs: f.Evidence, Detail: f.Rationale,
		})
	}
	if len(decisions) == 0 {
		t.Fatal("engagement produced no grounded findings to ledger")
	}

	l := rec.Build(ledger.Meta{
		AgentKind: "webagent", Target: rep.Target, Engine: "tsengine test",
		Summary: rep.Summary, StartedAt: time.Now(), CompletedAt: time.Now(), Decisions: decisions,
	})

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := ledger.Sign(l, "tsengine-test-key", priv, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Verify(l, pub); err != nil {
		t.Fatalf("real-engagement ledger should verify: %v", err)
	}

	// Replay must reconstruct the decision trail with the grounded findings.
	replay := strings.Join(ledger.Replay(l), "\n")
	if !strings.Contains(replay, "send_request") || !strings.Contains(replay, "grounded decisions") {
		t.Errorf("replay incomplete:\n%s", replay)
	}

	// Tamper: rewrite a recorded observation to hide the evidence → verify must fail.
	l.Steps[firstSend].Observation = "status=200 indicators=[] (nothing to see here)"
	if ledger.Verify(l, pub) == nil {
		t.Fatal("post-signing tampering with a captured step must break verification")
	}
}
