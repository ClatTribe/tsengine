package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/correlate"
)

func TestAnnotateLiveRisk(t *testing.T) {
	chains := []correlate.Chain{{Steps: []correlate.Step{{FindingID: "f-exposed-onpath"}, {FindingID: "x"}}}}

	issues := []Issue{
		// 1. observed under attack → live regardless of anything else
		{Key: "k1", Title: "SQLi", Severity: "medium", Attacked: true, FindingIDs: []string{"a"}},
		// 2. internet-exposed (http endpoint) AND a step in an attack path → live
		{Key: "k2", Title: "open redirect", Severity: "low", Endpoint: "https://app.acme.com/go", FindingIDs: []string{"f-exposed-onpath"}},
		// 3. exposed via marker + high + confirmed → live
		{Key: "k3", Title: "S3 bucket publicly readable", Severity: "high", Confirmed: true, FindingIDs: []string{"b"}},
		// 4. internal, not attacked, not on a path → NOT live (the static-posture majority)
		{Key: "k4", Title: "outdated dependency", Severity: "high", Endpoint: "/src/app.go:42", FindingIDs: []string{"c"}},
		// 5. exposed but low-severity, unconfirmed, not on a path → NOT live (exposure alone isn't enough)
		{Key: "k5", Title: "missing header", Severity: "low", Endpoint: "https://app.acme.com", FindingIDs: []string{"d"}},
	}

	live := AnnotateLiveRisk(issues, chains)
	if live != 3 {
		t.Fatalf("want 3 live issues, got %d", live)
	}
	want := map[string]bool{"k1": true, "k2": true, "k3": true, "k4": false, "k5": false}
	for _, i := range issues {
		if i.Live != want[i.Key] {
			t.Errorf("%s: Live=%v want %v (reason=%q)", i.Key, i.Live, want[i.Key], i.LiveReason)
		}
		if i.Live && i.LiveReason == "" {
			t.Errorf("%s: live issue must carry a reason", i.Key)
		}
	}
	// grounded sub-signals
	k2 := findIssue(issues, "k2")
	if !k2.Exposed || !k2.InAttackPath {
		t.Errorf("k2 should be exposed + in-attack-path, got %+v", k2)
	}
	k5 := findIssue(issues, "k5")
	if !k5.Exposed || k5.InAttackPath || k5.Live {
		t.Errorf("k5 should be exposed but not on-path and not live, got %+v", k5)
	}
}

func findIssue(issues []Issue, key string) Issue {
	for _, i := range issues {
		if i.Key == key {
			return i
		}
	}
	return Issue{}
}
