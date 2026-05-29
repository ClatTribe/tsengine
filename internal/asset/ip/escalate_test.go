package ip

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/hydra"
)

// Auth-bearing ports → hydra default-cred check on that exact host:port;
// non-auth ports (80/443) are skipped.
func TestPlanEscalation_HydraOnAuthServices(t *testing.T) {
	h := NewHandler()
	surface := []string{
		"10.0.0.5", "10.0.0.5:22", "10.0.0.5:3306", "10.0.0.5:80", "10.0.0.5:443",
	}
	out := h.PlanEscalation(types.Asset{Type: types.AssetIPAddress, Target: "10.0.0.5"}, surface, nil)

	svcByTargetPort := map[string]string{}
	for _, d := range out {
		if d.Tool.Name() != "hydra" {
			t.Fatalf("unexpected escalation tool %q", d.Tool.Name())
		}
		svcByTargetPort[d.Args["service"].(string)] = d.EscalatedFrom
	}
	if len(out) != 2 {
		t.Fatalf("hydra dispatches = %d, want 2 (ssh + mysql; http skipped)", len(out))
	}
	if _, ok := svcByTargetPort["ssh"]; !ok {
		t.Error("expected hydra ssh on port 22")
	}
	if _, ok := svcByTargetPort["mysql"]; !ok {
		t.Error("expected hydra mysql on port 3306")
	}
}

func TestPlanEscalation_NoAuthServicesNoHydra(t *testing.T) {
	h := NewHandler()
	out := h.PlanEscalation(types.Asset{Type: types.AssetIPAddress, Target: "10.0.0.5"},
		[]string{"10.0.0.5", "10.0.0.5:80", "10.0.0.5:443"}, nil)
	if len(out) != 0 {
		t.Errorf("no auth services → no hydra; got %d", len(out))
	}
}

func TestHydraServiceForPort(t *testing.T) {
	if s, ok := hydraServiceForPort(22); !ok || s != "ssh" {
		t.Errorf("port 22 = %q,%v", s, ok)
	}
	if _, ok := hydraServiceForPort(80); ok {
		t.Error("port 80 is not an auth service")
	}
}
