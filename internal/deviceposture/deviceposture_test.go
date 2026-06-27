package deviceposture

import (
	"testing"
	"time"
)

func TestAssess_DeviceRisks(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	// a fully non-compliant device trips every check
	bad := Device{Name: "laptop-1", Owner: "eng@acme.io", OS: "macos", OSVersion: "10.13",
		DiskEncrypted: false, ScreenLock: false, FirewallOn: false, EDR: false, AutoUpdate: false,
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
		DiskEncrypted: true, ScreenLock: true, FirewallOn: true, EDR: true, AutoUpdate: true}
	if f := Assess([]Device{good}, Options{Now: now}); len(f) != 0 {
		t.Errorf("a compliant device must yield zero findings, got %d: %+v", len(f), f)
	}
}
