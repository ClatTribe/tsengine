package retest

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func applied(id string, keys ...string) platform.Action {
	return platform.Action{ID: id, TenantID: "t", Status: platform.ActApplied, FindingKeys: keys}
}
func find(rule, endpoint string) types.Finding {
	return types.Finding{ID: rule + endpoint, RuleID: rule, Endpoint: endpoint}
}

var t0 = time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)

// The vuln an applied fix targeted is GONE from the fresh scan → verified "fixed" (grounded on absence).
func TestVerify_AbsentFindingMarkedFixed(t *testing.T) {
	acts := []platform.Action{applied("a1", "sqli|/search")}
	current := []types.Finding{find("xss", "/other")} // sqli|/search is gone
	changed := Verify(acts, current, t0)
	if len(changed) != 1 {
		t.Fatalf("want 1 changed, got %d", len(changed))
	}
	v := changed[0].Verification
	if v == nil || v.Status != "fixed" {
		t.Fatalf("want fixed, got %+v", v)
	}
	if len(v.Fixed) != 1 || len(v.StillPresent) != 0 {
		t.Errorf("fixed/still mismatch: %+v", v)
	}
}

// The vuln is STILL present → "still_present" (the fix didn't work; never falsely says fixed).
func TestVerify_PresentFindingMarkedStillPresent(t *testing.T) {
	acts := []platform.Action{applied("a1", "sqli|/search")}
	current := []types.Finding{find("sqli", "/search")} // still there
	changed := Verify(acts, current, t0)
	if len(changed) != 1 || changed[0].Verification.Status != "still_present" {
		t.Fatalf("want still_present, got %+v", changed)
	}
	if len(changed[0].Verification.StillPresent) != 1 {
		t.Errorf("want 1 still-present key, got %+v", changed[0].Verification)
	}
}

// A bulk fix is "fixed" only when ALL its keys are gone; one survivor → still_present.
func TestVerify_BulkPartialIsStillPresent(t *testing.T) {
	acts := []platform.Action{applied("a1", "sqli|/a", "xss|/b", "ssrf|/c")}
	current := []types.Finding{find("xss", "/b")} // 2 fixed, 1 remains
	changed := Verify(acts, current, t0)
	v := changed[0].Verification
	if v.Status != "still_present" || len(v.Fixed) != 2 || len(v.StillPresent) != 1 {
		t.Fatalf("partial bulk: %+v", v)
	}
}

// Grounding §10: an applied action with NO finding keys is never guessed — left un-verified.
func TestVerify_NoKeysLeftUnverified(t *testing.T) {
	acts := []platform.Action{{ID: "a1", TenantID: "t", Status: platform.ActApplied}}
	if changed := Verify(acts, nil, t0); len(changed) != 0 {
		t.Fatalf("no-keys action must not be verified, got %+v", changed)
	}
}

// Only APPLIED actions are verified — a still-pending one is skipped.
func TestVerify_PendingActionSkipped(t *testing.T) {
	acts := []platform.Action{{ID: "a1", TenantID: "t", Status: platform.ActPendingApproval, FindingKeys: []string{"sqli|/x"}}}
	if changed := Verify(acts, nil, t0); len(changed) != 0 {
		t.Fatalf("pending action must not be verified, got %+v", changed)
	}
}

// Idempotent: re-running over the same scan re-emits nothing, and "fixed" is terminal even if the
// vuln later reappears (that regression is detect.Reconcile's job, not a re-flip here).
func TestVerify_IdempotentAndFixedIsTerminal(t *testing.T) {
	acts := []platform.Action{applied("a1", "sqli|/search")}
	changed := Verify(acts, nil, t0) // fixed
	if len(changed) != 1 {
		t.Fatalf("first pass should mark fixed")
	}
	verified := changed[0]
	// Same clean scan again → no change.
	if again := Verify([]platform.Action{verified}, nil, t0); len(again) != 0 {
		t.Fatalf("idempotent re-run should change nothing, got %+v", again)
	}
	// Vuln reappears → NOT re-flipped (terminal fixed).
	reappeared := []types.Finding{find("sqli", "/search")}
	if again := Verify([]platform.Action{verified}, reappeared, t0); len(again) != 0 {
		t.Fatalf("fixed is terminal; reappearance is a new incident not a re-flip, got %+v", again)
	}
}

// still_present is NOT terminal — a later clean scan upgrades it to fixed.
func TestVerify_StillPresentUpgradesToFixed(t *testing.T) {
	acts := []platform.Action{applied("a1", "sqli|/search")}
	chg := Verify(acts, []types.Finding{find("sqli", "/search")}, t0) // still_present
	if chg[0].Verification.Status != "still_present" {
		t.Fatal("setup")
	}
	chg2 := Verify([]platform.Action{chg[0]}, nil, t0) // now gone
	if len(chg2) != 1 || chg2[0].Verification.Status != "fixed" {
		t.Fatalf("still_present should upgrade to fixed, got %+v", chg2)
	}
}

func TestKeysForIDs(t *testing.T) {
	findings := []types.Finding{find("sqli", "/a"), find("xss", "/b"), find("ssrf", "/c")}
	got := KeysForIDs([]string{"sqli/a", "ssrf/c", "missing"}, findings)
	if len(got) != 2 || got[0] != "sqli|/a" || got[1] != "ssrf|/c" {
		t.Fatalf("KeysForIDs: %+v", got)
	}
}
