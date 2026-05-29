package hydra

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_HydraHit(t *testing.T) {
	out := []byte(`[DATA] attacking ssh://10.0.0.5:22/
[22][ssh] host: 10.0.0.5   login: root   password: toor
1 of 1 target successfully completed`)
	findings := parse(out, "10.0.0.5", "ssh")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != types.SeverityCritical || f.RuleID != "hydra::default-credentials" {
		t.Errorf("finding = %+v", f)
	}
	if f.ToolArgs["login"] != "root" {
		t.Errorf("login = %q, want root", f.ToolArgs["login"])
	}
}

func TestParse_NoHit(t *testing.T) {
	if f := parse([]byte("0 of 1 target completed, 0 valid passwords found"), "h", "ssh"); len(f) != 0 {
		t.Errorf("want no findings, got %d", len(f))
	}
}

func TestRun_RejectsBadService(t *testing.T) {
	if _, err := New().Run(context.Background(), tool.Args{"target": "h", "service": "carrierpigeon"}); err == nil {
		t.Error("expected error for unsupported service")
	}
	if _, err := New().Run(context.Background(), tool.Args{"target": "h"}); err == nil {
		t.Error("expected error for missing service")
	}
}

func TestHydra_Identity(t *testing.T) {
	if _, ok := tool.Get("hydra"); !ok {
		t.Error("hydra not registered")
	}
}
