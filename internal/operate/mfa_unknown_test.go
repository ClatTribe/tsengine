package operate

import (
	"strings"
	"testing"
	"time"
)

// The worst finding this engine can produce is a CRITICAL one that is not true.
//
// Okta reads MFA factors with a per-user call. The caller correctly declined to assign on error —
// and MFA's zero value is false, which is the value checkAdminMFA fires on. So a failed factor read
// published "Administrator without MFA: alice@corp" at CRITICAL, mapped to twelve compliance
// frameworks, against an admin who has MFA enrolled. It happens exactly when an org is large enough
// to hit Okta's rate limits, which is the org where a fabricated critical costs the most.
func TestAssess_DoesNotInventAnMFAFindingForAUserItCouldNotRead(t *testing.T) {
	now := time.Now().UTC()
	ws := Workspace{
		Provider: "okta",
		Users: []User{
			{Email: "alice@corp.example", Admin: true, MFAUnknown: true},
			{Email: "bob@corp.example", MFAUnknown: true},
		},
	}
	for _, f := range Assess(ws, Options{Now: now}) {
		if strings.Contains(f.RuleID, "without-mfa") {
			t.Errorf("fabricated %s (%s) for a user whose MFA state was never read: %s",
				f.Severity, f.RuleID, f.Title)
		}
	}
}

// The other half, and the one that keeps this from being a way to silence findings: a user we DID
// read and who genuinely has no MFA must still be reported.
func TestAssess_StillReportsAnAdminWeReadAndWhoHasNoMFA(t *testing.T) {
	now := time.Now().UTC()
	ws := Workspace{Provider: "okta", Users: []User{{Email: "carol@corp.example", Admin: true}}}
	var found bool
	for _, f := range Assess(ws, Options{Now: now}) {
		if f.RuleID == "operate::admin-without-mfa" {
			found = true
		}
	}
	if !found {
		t.Fatal("an admin whose MFA WAS read and is absent is the highest-leverage finding here — " +
			"suppressing it would trade a false positive for a false negative")
	}
}

// A posted snapshot asserts its values directly and never sets MFAUnknown, so mfa:false keeps
// meaning no MFA. The fix has to be additive or it silently disarms every snapshot-driven tenant.
func TestAssess_PostedSnapshotBehaviourIsUnchanged(t *testing.T) {
	now := time.Now().UTC()
	ws := Workspace{Provider: "gworkspace", Users: []User{{Email: "dan@corp.example", MFA: false}}}
	var found bool
	for _, f := range Assess(ws, Options{Now: now}) {
		if f.RuleID == "operate::user-without-mfa" {
			found = true
		}
	}
	if !found {
		t.Error("a snapshot asserting mfa:false still means no MFA")
	}
}

// And the gap must be DISCLOSED, not merely suppressed. Suppressing alone converts a false positive
// into a silent false negative, which is the trade coverage.go exists to refuse.
func TestAssess_DisclosesTheUnreadMFACheck(t *testing.T) {
	now := time.Now().UTC()
	ws := Workspace{
		Provider:    "okta",
		Users:       []User{{Email: "alice@corp.example", Admin: true, MFAUnknown: true}},
		Unavailable: []string{"mfa"},
	}
	var disclosed bool
	for _, f := range Assess(ws, Options{Now: now}) {
		if strings.HasPrefix(f.RuleID, coverageRulePrefix) && strings.Contains(f.RuleID, "mfa") {
			disclosed = true
		}
	}
	if !disclosed {
		t.Error("suppressing the finding without saying the check did not run turns a fabricated " +
			"critical into a clean MFA posture — the same trade in the other direction")
	}
}
