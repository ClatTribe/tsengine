package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/improveloop"
)

// A journal we cannot read must be REFUSED, never treated as empty. Next answers an empty baseline
// with "nothing to improve", so defaulting would turn a missing file into a finished loop — the
// clean-because-we-did-not-look answer.
func TestImproveCmd_RefusesAnUnreadableJournal(t *testing.T) {
	err := improveCmd([]string{"--journal", filepath.Join(t.TempDir(), "absent.json")})
	if err == nil {
		t.Fatal("a missing journal was accepted — the loop would report itself finished")
	}
	if !strings.Contains(err.Error(), "cannot read") {
		t.Errorf("the error must say the file could not be read: %v", err)
	}
}

// Malformed JSON is the same class: a file we could not parse is not a baseline.
func TestImproveCmd_RefusesMalformedJournal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := improveCmd([]string{"--journal", p})
	if err == nil || !strings.Contains(err.Error(), "refusing to decide") {
		t.Errorf("malformed JSON must be refused explicitly, got %v", err)
	}
}

// No journal at all is refused rather than defaulted, for the same reason.
func TestImproveCmd_RequiresAJournal(t *testing.T) {
	if err := improveCmd(nil); err == nil {
		t.Fatal("the command decided without a journal")
	}
}

// BLOCKED capabilities must be printed, in both branches. A loop that quietly stops working on
// something is indistinguishable from one that finished it.
func TestRenderDecision_AlwaysReportsBlocked(t *testing.T) {
	blocked := map[string]string{"exploit-verification": "decoy control failed"}

	stopped := renderDecision(improveloop.Decision{
		Done: true, Why: "budget exhausted", Blocked: blocked,
	}, 3, 2)
	if !strings.Contains(stopped, "exploit-verification") || !strings.Contains(stopped, "decoy control failed") {
		t.Errorf("a stopped loop hid what it had given up on:\n%s", stopped)
	}

	running := renderDecision(improveloop.Decision{
		Target: improveloop.Measurement{Capability: "remediation", Score: 0.5}, Blocked: blocked,
	}, 3, 1)
	if !strings.Contains(running, "exploit-verification") {
		t.Errorf("a running loop hid what it had given up on:\n%s", running)
	}
}

// The stop REASON must survive to the output: "why we stopped" is the whole value of the render.
func TestRenderDecision_StatesWhyItStopped(t *testing.T) {
	out := renderDecision(improveloop.Decision{
		Done: true, Why: "the last round bought 0.001 per dollar, below the floor",
	}, 4, 3)
	if !strings.Contains(out, "below the floor") {
		t.Errorf("the stop reason was dropped:\n%s", out)
	}
}
