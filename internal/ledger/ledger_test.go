package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	n := 0
	return func() time.Time {
		n++
		return t.Add(time.Duration(n) * time.Second)
	}
}

// recordSample drives a Recorder through a small but representative agent run:
// a tool dispatch, a malformed-action note, another dispatch that commits a finding.
func recordSample() *Recorder {
	r := NewRecorder().WithClock(fixedClock())
	r.Record("probe the search param", "send_request",
		map[string]any{"method": "GET", "url": "https://app/search?q='", "payload": "'"},
		"t-001  status=500  indicators=[sql_error]")
	r.Note("invalid action: not valid JSON")
	r.Record("the sql_error proves it", "record_finding",
		map[string]any{"route": "https://app/search?q=", "class": "sqli", "evidence": []any{"t-001"}},
		"recorded web-001 (sqli) — grounded by the \"sql_error\" indicator")
	return r
}

func sampleLedger() *Ledger {
	return recordSample().Build(Meta{
		EngagementID: "eng-1", AgentKind: "webagent", Target: "https://app",
		Engine: "tsengine test", Summary: "1 finding",
		StartedAt:   time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 6, 9, 12, 5, 0, 0, time.UTC),
		Decisions: []Decision{{
			ID: "web-001", Kind: "sqli", Severity: "high",
			Refs: []string{"t-001"}, Detail: "error-based SQLi",
		}},
	})
}

func TestRecorderCapturesEveryStep(t *testing.T) {
	l := sampleLedger()
	if l.Version != SchemaVersion {
		t.Errorf("version = %q", l.Version)
	}
	if len(l.Steps) != 3 {
		t.Fatalf("want 3 steps (2 dispatch + 1 note), got %d", len(l.Steps))
	}
	// sequence numbers are dense and ordered
	for i, s := range l.Steps {
		if s.Seq != i+1 {
			t.Errorf("step %d Seq = %d", i, s.Seq)
		}
	}
	if l.Steps[0].Tool != "send_request" || l.Steps[0].Args["payload"] != "'" {
		t.Errorf("step 0 wrong: %+v", l.Steps[0])
	}
	if l.Steps[1].Note == "" || l.Steps[1].Tool != "" {
		t.Errorf("step 1 should be a note: %+v", l.Steps[1])
	}
	if l.Steps[2].Tool != "record_finding" {
		t.Errorf("step 2 tool = %q", l.Steps[2].Tool)
	}
	if len(l.Decisions) != 1 || l.Decisions[0].ID != "web-001" {
		t.Errorf("decisions wrong: %+v", l.Decisions)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l := sampleLedger()
	now := time.Date(2026, 6, 9, 12, 6, 0, 0, time.UTC)
	if err := Sign(l, "tsengine-test-key", priv, now); err != nil {
		t.Fatal(err)
	}
	if l.Attestation == nil || l.Attestation.Signer != "tsengine-test-key" {
		t.Fatalf("attestation not populated: %+v", l.Attestation)
	}
	if err := Verify(l, pub); err != nil {
		t.Fatalf("fresh ledger should verify: %v", err)
	}
	// a different key must NOT verify
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if Verify(l, otherPub) == nil {
		t.Error("verify should fail against a different public key")
	}
}

func TestExportLoadVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l := sampleLedger()
	if err := Sign(l, "k", priv, time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "led.json")
	if err := Export(path, l); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// survives the disk round-trip: signature still valid (canonical form stable)
	if err := Verify(got, pub); err != nil {
		t.Fatalf("loaded ledger should verify: %v", err)
	}
	if len(got.Steps) != 3 || got.Decisions[0].ID != "web-001" {
		t.Errorf("round-trip lost data: %d steps, decisions=%+v", len(got.Steps), got.Decisions)
	}
}

func TestTamperDetected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l := sampleLedger()
	if err := Sign(l, "k", priv, time.Now()); err != nil {
		t.Fatal(err)
	}
	// flip a recorded observation AFTER signing — the auditor's nightmare
	l.Steps[0].Observation = "t-001  status=200  indicators=[]"
	if err := Verify(l, pub); err == nil {
		t.Fatal("tampering with a step must break verification")
	} else if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("want hash mismatch, got %v", err)
	}

	// adding a fabricated decision must also break it
	l2 := sampleLedger()
	_ = Sign(l2, "k", priv, time.Now())
	l2.Decisions = append(l2.Decisions, Decision{ID: "web-999", Kind: "rce", Severity: "critical"})
	if Verify(l2, pub) == nil {
		t.Fatal("a fabricated decision must break verification")
	}
}

func TestReplayReconstructsSequence(t *testing.T) {
	lines := Replay(sampleLedger())
	joined := strings.Join(lines, "\n")
	// every dispatched tool, in order, plus the note and the grounded decision
	for _, want := range []string{
		"#1", "send_request", "indicators=[sql_error]",
		"#2", "invalid action",
		"#3", "record_finding",
		"grounded decisions", "web-001", "sqli", "evidence=[t-001]",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("replay missing %q in:\n%s", want, joined)
		}
	}
	// order: send_request before record_finding
	if strings.Index(joined, "send_request") > strings.Index(joined, "record_finding") {
		t.Error("replay steps out of order")
	}
}

func TestNilRecorderIsNoop(t *testing.T) {
	var r *Recorder // nil
	// none of these may panic
	r.Record("t", "tool", map[string]any{"a": 1}, "obs")
	r.Note("x")
	if r.Len() != 0 || r.Steps() != nil {
		t.Error("nil recorder should stay empty")
	}
}
