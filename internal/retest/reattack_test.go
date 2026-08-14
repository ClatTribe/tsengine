package retest

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

var raNow = time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)

// appliedAction returns an applied remediation that claimed to fix the given keys, with an optional
// prior rescan verdict.
func appliedAction(id string, rescanStatus string, keys ...string) platform.Action {
	a := platform.Action{ID: id, Status: platform.ActApplied, FindingKeys: keys}
	if rescanStatus != "" {
		a.Verification = &platform.FixVerification{Status: rescanStatus, Method: "rescan"}
	}
	return a
}

// ══ THE CASE THIS EXISTS FOR ═════════════════════════════════════════════════════════════════════
//
// The rescan says fixed and the exploit still works. Nothing in an absence-based check can catch it,
// and the customer has been told they are safe.
func TestApplyReattack_RescanSaidFixedButExploitStillWorks(t *testing.T) {
	acts := []platform.Action{appliedAction("a1", "fixed", "sqli|/search")}
	got := ApplyReattack(acts, map[string]ReattackVerdict{
		"sqli|/search": {Exploitable: true, Verified: true, Evidence: "the canary was still reflected"},
	}, raNow)

	if len(got) != 1 {
		t.Fatalf("want 1 changed action, got %d", len(got))
	}
	v := got[0].Verification
	if v.Status != StatusStillExploitable {
		t.Fatalf("status = %q, want still_exploitable — a live exploit must beat a scanner's silence", v.Status)
	}
	if v.Method != MethodReattack {
		t.Errorf("method = %q, want reattack so the stronger evidence is attributable", v.Method)
	}
	if !strings.Contains(v.Evidence, "still succeed") {
		t.Errorf("evidence does not state what was observed: %q", v.Evidence)
	}
}

// Both kinds of evidence agree → the strongest claim the product can make.
func TestApplyReattack_BothAgreeIsClosedWithProof(t *testing.T) {
	acts := []platform.Action{appliedAction("a1", "fixed", "xss|/q")}
	got := ApplyReattack(acts, map[string]ReattackVerdict{
		"xss|/q": {Exploitable: false, Verified: true},
	}, raNow)

	if len(got) != 1 || got[0].Verification.Status != StatusClosedWithProof {
		t.Fatalf("want closed_with_proof, got %+v", got)
	}
	if !strings.Contains(got[0].Verification.Evidence, "not just absence") {
		t.Errorf("evidence does not distinguish closure from absence: %q", got[0].Verification.Evidence)
	}
}

// ONE LIVE EXPLOIT BEATS SEVERAL CLOSURES. Reporting a partial closure as success is how someone stops
// looking at a hole that is still open.
func TestApplyReattack_OneExploitableKeySinksTheWholeAction(t *testing.T) {
	acts := []platform.Action{appliedAction("a1", "fixed", "k1", "k2", "k3")}
	got := ApplyReattack(acts, map[string]ReattackVerdict{
		"k1": {Exploitable: false, Verified: true},
		"k2": {Exploitable: false, Verified: true},
		"k3": {Exploitable: true, Verified: true, Evidence: "still reflected"},
	}, raNow)

	v := got[0].Verification
	if v.Status != StatusStillExploitable {
		t.Fatalf("2 of 3 closed and 1 still live was graded %q — partial closure is not success", v.Status)
	}
	if len(v.StillPresent) != 1 || len(v.Fixed) != 2 {
		t.Errorf("the split was lost: still=%v fixed=%v", v.StillPresent, v.Fixed)
	}
}

// ══ THE REFUSALS ═════════════════════════════════════════════════════════════════════════════════

// Unverifiable changes NOTHING. We do not upgrade on absence of evidence, and we do not downgrade on
// it either — the rescan verdict stands as it was.
func TestApplyReattack_UnverifiableLeavesTheRescanVerdictAlone(t *testing.T) {
	acts := []platform.Action{appliedAction("a1", "fixed", "k1")}
	got := ApplyReattack(acts, map[string]ReattackVerdict{
		"k1": {Exploitable: false, Verified: false, Evidence: "no playbook for this class"},
	}, raNow)

	if len(got) != 0 {
		t.Fatalf("an unverified re-attack changed the verdict to %+v", got[0].Verification)
	}
}

// An unverified verdict must never be read as "not exploitable". This is the same false-all-clear the
// pentest side refuses, asserted again here because the merge is a second place it could leak in.
func TestApplyReattack_UnverifiedIsNotTreatedAsClosed(t *testing.T) {
	acts := []platform.Action{appliedAction("a1", "still_present", "k1")}
	got := ApplyReattack(acts, map[string]ReattackVerdict{
		"k1": {Exploitable: false, Verified: false},
	}, raNow)
	for _, a := range got {
		if a.Verification.Status == StatusClosedWithProof {
			t.Fatal("an UNVERIFIED re-attack was promoted to closed_with_proof")
		}
	}
}

// A disagreement — exploit dead but the scanner still sees it — is reported as partial rather than
// resolved in whichever direction flatters us. The scanner may be seeing a variant we do not cover.
func TestApplyReattack_DisagreementIsReportedNotHidden(t *testing.T) {
	acts := []platform.Action{appliedAction("a1", "still_present", "k1")}
	got := ApplyReattack(acts, map[string]ReattackVerdict{
		"k1": {Exploitable: false, Verified: true},
	}, raNow)

	if len(got) != 1 {
		t.Fatalf("want 1 changed action, got %d", len(got))
	}
	if !strings.Contains(strings.ToLower(got[0].Verification.Evidence), "partial") {
		t.Errorf("the scanner/exploit disagreement was not surfaced: %q", got[0].Verification.Evidence)
	}
}

// Same gate as Verify: an action with no keys, or one that was never applied, is left alone rather
// than guessed at.
func TestApplyReattack_SkipsUngroundableActions(t *testing.T) {
	acts := []platform.Action{
		{ID: "no-keys", Status: platform.ActApplied},
		{ID: "not-applied", Status: platform.ActPendingApproval, FindingKeys: []string{"k1"}},
	}
	if got := ApplyReattack(acts, map[string]ReattackVerdict{"k1": {Exploitable: true, Verified: true}}, raNow); len(got) != 0 {
		t.Errorf("changed %d ungroundable actions", len(got))
	}
}

func TestApplyReattack_NoVerdictsIsANoOp(t *testing.T) {
	acts := []platform.Action{appliedAction("a1", "fixed", "k1")}
	if got := ApplyReattack(acts, nil, raNow); got != nil {
		t.Errorf("no verdicts should change nothing, got %d", len(got))
	}
}

// The key vocabulary must match Verify's exactly, or the two halves silently stop referring to the
// same findings.
func TestApplyReattack_UsesTheSameKeysAsVerify(t *testing.T) {
	acts := []platform.Action{appliedAction("a1", "fixed", "rule|endpoint")}
	got := ApplyReattack(acts, map[string]ReattackVerdict{"rule|endpoint": {Exploitable: true, Verified: true}}, raNow)
	if len(got) != 1 {
		t.Fatal("a verdict keyed exactly as Verify keys did not match — the two halves have drifted")
	}
}
