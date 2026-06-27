package protect

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

var t0 = time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)

func ev(app, kind, endpoint string, blocked bool, at time.Time) platform.RuntimeEvent {
	return platform.RuntimeEvent{App: app, AttackKind: kind, Endpoint: endpoint, Blocked: blocked, Source: "zen", OccurredAt: at}
}

func TestCompute_BlocksAndMonitors(t *testing.T) {
	events := []platform.RuntimeEvent{
		ev("api", "sql_injection", "/search", true, t0),
		ev("api", "sql_injection", "/search", true, t0),
		ev("api", "ssrf", "/fetch", true, t0),
		ev("web", "xss", "/profile", false, t0), // monitor-only
	}
	s := Compute(events, time.Time{}, 10)
	if !s.Active {
		t.Fatal("events present → protection active")
	}
	if s.TotalAttacks != 4 || s.Blocked != 3 || s.MonitorOnly != 1 {
		t.Fatalf("counts: %+v", s)
	}
	if s.BlockRate < 0.74 || s.BlockRate > 0.76 {
		t.Errorf("block rate should be 0.75, got %v", s.BlockRate)
	}
	if len(s.Apps) != 2 || s.Apps[0] != "api" || s.Apps[1] != "web" {
		t.Errorf("apps: %+v", s.Apps)
	}
	if len(s.Sensors) != 1 || s.Sensors[0] != "zen" {
		t.Errorf("sensors: %+v", s.Sensors)
	}
	// most frequent attack kind first.
	if s.ByAttackKind[0].Kind != "sql_injection" || s.ByAttackKind[0].Count != 2 {
		t.Errorf("top kind: %+v", s.ByAttackKind)
	}
	// most-targeted endpoint first.
	if s.TopEndpoints[0].Endpoint != "/search" || s.TopEndpoints[0].Count != 2 || s.TopEndpoints[0].Blocked != 2 {
		t.Errorf("top endpoint: %+v", s.TopEndpoints)
	}
}

// Grounded §10: no events → not "protected", just no signal.
func TestCompute_NoSignal(t *testing.T) {
	s := Compute(nil, time.Time{}, 10)
	if s.Active || s.TotalAttacks != 0 || s.BlockRate != 0 {
		t.Fatalf("no events must be inactive/zero, got %+v", s)
	}
}

// Monitor-only deployment: active, but block rate 0 (honest — monitoring, not blocking).
func TestCompute_MonitorOnlyIsHonest(t *testing.T) {
	s := Compute([]platform.RuntimeEvent{ev("api", "xss", "/x", false, t0)}, time.Time{}, 10)
	if !s.Active || s.Blocked != 0 || s.BlockRate != 0 || s.MonitorOnly != 1 {
		t.Fatalf("monitor-only: %+v", s)
	}
}

// The `since` window excludes older events.
func TestCompute_SinceWindow(t *testing.T) {
	old := ev("api", "xss", "/x", true, t0.Add(-48*time.Hour))
	recent := ev("api", "xss", "/x", true, t0)
	s := Compute([]platform.RuntimeEvent{old, recent}, t0.Add(-1*time.Hour), 10)
	if s.TotalAttacks != 1 {
		t.Fatalf("only the recent event should count, got %d", s.TotalAttacks)
	}
}
