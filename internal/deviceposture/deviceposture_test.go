package deviceposture

import (
	"testing"
	"time"
)

// b is the pointer helper: the five protective settings distinguish "reported off" from "not
// reported at all", so a test must say which one it means.
func b(v bool) *bool { return &v }

func TestAssess_DeviceRisks(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	// a fully non-compliant device trips every check
	bad := Device{Name: "laptop-1", Owner: "eng@acme.io", OS: "macos", OSVersion: "10.13",
		DiskEncrypted: b(false), ScreenLock: b(false), FirewallOn: b(false), EDR: b(false), AutoUpdate: b(false),
		OSEndOfLife: true, Jailbroken: true}
	got := map[string]bool{}
	for _, f := range Assess([]Device{bad}, Options{Now: now}) {
		got[f.RuleID] = true
		if f.Compliance == nil {
			t.Errorf("%s missing compliance", f.RuleID)
		}
	}
	for _, want := range []string{
		"deviceposture::disk-unencrypted", "deviceposture::tampered", "deviceposture::os-end-of-life",
		"deviceposture::no-screen-lock", "deviceposture::firewall-off", "deviceposture::no-edr",
		"deviceposture::auto-update-off",
	} {
		if !got[want] {
			t.Errorf("expected device finding %q", want)
		}
	}
}

// A compliant device yields ZERO findings (grounded, not noise).
func TestAssess_CompliantFleet(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	good := Device{Name: "ok", OS: "macos", OSVersion: "14.5",
		DiskEncrypted: b(true), ScreenLock: b(true), FirewallOn: b(true), EDR: b(true), AutoUpdate: b(true)}
	if f := Assess([]Device{good}, Options{Now: now}); len(f) != 0 {
		t.Errorf("a compliant device must yield zero findings, got %d: %+v", len(f), f)
	}
}

// ── ABSENT IS NOT OFF ────────────────────────────────────────────────────────────────────────────

// The Device type has always promised that "a missing field is not a finding — absent data never
// invents risk". As plain bools it could not keep that promise: a device reporting only its name and
// disk state produced four findings about settings it never mentioned, and the ingest reported that
// nothing had been skipped.
//
// That is not a display bug. Those findings open incidents, carry compliance mappings, and reach an
// auditor's evidence pack — so an MDM export that simply names its fields differently (Jamf, Kandji
// and Intune all do) manufactured evidence of a control failure that was never observed.
func TestUnreportedSettings_AreNotFindings(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	partial := Device{Name: "minimal", Owner: "eng@acme.io", DiskEncrypted: b(true)}

	got := Assess([]Device{partial}, Options{Now: now})
	if len(got) != 0 {
		t.Fatalf("a device that reported only its disk state produced %d finding(s) about settings it "+
			"never mentioned: %+v", len(got), got)
	}
}

// But a setting explicitly recorded as OFF is still a finding — the fix must not buy silence by
// going blind. This is the half that keeps the change honest in both directions.
func TestExplicitlyOffSettings_AreStillFindings(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	off := Device{Name: "reported-off", Owner: "eng@acme.io", FirewallOn: b(false), EDR: b(false)}

	rules := map[string]bool{}
	for _, f := range Assess([]Device{off}, Options{Now: now}) {
		rules[f.RuleID] = true
	}
	for _, want := range []string{"deviceposture::firewall-off", "deviceposture::no-edr"} {
		if !rules[want] {
			t.Errorf("a setting reported as off produced no %s finding: %v", want, rules)
		}
	}
	// And it must not invent the three it was not told about.
	for _, unwanted := range []string{
		"deviceposture::disk-unencrypted", "deviceposture::no-screen-lock", "deviceposture::auto-update-off",
	} {
		if rules[unwanted] {
			t.Errorf("%s was reported for a setting the device never mentioned", unwanted)
		}
	}
}
