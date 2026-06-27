package runner

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/retest"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The runner stamps an applied action's stable finding keys at propose time, and a later clean
// re-scan verifies the fix — the full KF#4 loop at the runner layer (stamp → apply → re-test).
func TestStampFindingKeys_ThenVerifyConfirmsFix(t *testing.T) {
	f := types.Finding{ID: "f-001", RuleID: "nuclei::sqli", Endpoint: "https://app/search", Severity: types.SeverityHigh}

	// Propose-time: the runner stamps the finding's stable key onto the action.
	act := stampFindingKeys(platform.Action{ID: "a1", TenantID: "t", FindingID: f.ID}, []types.Finding{f})
	if len(act.FindingKeys) != 1 || act.FindingKeys[0] != "nuclei::sqli|https://app/search" {
		t.Fatalf("stampFindingKeys: %+v", act.FindingKeys)
	}

	// Apply it, then re-scan CLEAN (the vuln is gone) → verified fixed.
	act.Status = platform.ActApplied
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	changed := retest.Verify([]platform.Action{act}, nil, now)
	if len(changed) != 1 || changed[0].Verification == nil || changed[0].Verification.Status != "fixed" {
		t.Fatalf("clean re-scan should confirm fixed, got %+v", changed)
	}

	// Re-scan that STILL finds it → still_present (the fix didn't work).
	stillThere := retest.Verify([]platform.Action{act}, []types.Finding{f}, now)
	if len(stillThere) != 1 || stillThere[0].Verification.Status != "still_present" {
		t.Fatalf("vuln still present should NOT confirm fixed, got %+v", stillThere)
	}
}

// A bulk action carries every finding id it resolves; stampFindingKeys captures all their keys.
func TestStampFindingKeys_Bulk(t *testing.T) {
	findings := []types.Finding{
		{ID: "f1", RuleID: "sca::cve-1", Endpoint: "go.mod"},
		{ID: "f2", RuleID: "sca::cve-2", Endpoint: "go.mod"},
	}
	act := stampFindingKeys(platform.Action{ID: "a1", TenantID: "t", FindingID: "f1", FindingIDs: []string{"f1", "f2"}}, findings)
	if len(act.FindingKeys) != 2 {
		t.Fatalf("bulk stamp should capture 2 keys, got %+v", act.FindingKeys)
	}
}
