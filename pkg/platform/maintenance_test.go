package platform

import (
	"testing"
	"time"
)

func TestMaintenanceWindow_Active(t *testing.T) {
	base := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	w := MaintenanceWindow{StartsAt: base, EndsAt: base.Add(2 * time.Hour)}
	cases := []struct {
		name   string
		now    time.Time
		active bool
	}{
		{"before", base.Add(-time.Minute), false},
		{"at start", base, true},
		{"inside", base.Add(time.Hour), true},
		{"at end (exclusive)", base.Add(2 * time.Hour), false},
		{"after", base.Add(3 * time.Hour), false},
	}
	for _, c := range cases {
		if w.Active(c.now) != c.active {
			t.Errorf("%s: Active=%v want %v", c.name, w.Active(c.now), c.active)
		}
	}
}

func TestTenant_InMaintenance(t *testing.T) {
	base := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	tn := Tenant{MaintenanceWindows: []MaintenanceWindow{
		{ID: "past", StartsAt: base.Add(-3 * time.Hour), EndsAt: base.Add(-time.Hour)},
		{ID: "now", Name: "deploy", StartsAt: base.Add(-time.Hour), EndsAt: base.Add(time.Hour)},
	}}
	if w, ok := tn.InMaintenance(base); !ok || w.ID != "now" {
		t.Fatalf("should be in the active window 'now', got %+v ok=%v", w, ok)
	}
	if _, ok := tn.InMaintenance(base.Add(5 * time.Hour)); ok {
		t.Error("no window active 5h later")
	}
	if _, ok := (Tenant{}).InMaintenance(base); ok {
		t.Error("no windows → never in maintenance")
	}
}
