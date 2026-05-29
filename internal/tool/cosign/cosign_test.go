package cosign

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestAssess_Unsigned(t *testing.T) {
	// cosign tree found nothing (exit non-zero, empty output) → finding.
	out := assess([]byte("no signatures found"), false, "nginx:1.14")
	if len(out) != 1 || out[0].RuleID != "cosign::unsigned-image" {
		t.Fatalf("unsigned image should yield 1 finding, got %v", out)
	}
	if out[0].Severity != types.SeverityLow {
		t.Errorf("severity = %q, want low", out[0].Severity)
	}
}

func TestAssess_Signed(t *testing.T) {
	out := assess([]byte("📦 Supply Chain Security Related artifacts\n└── 🔐 Signatures\n   └── sha256:abc"), true, "img")
	if len(out) != 0 {
		t.Errorf("signed image should yield no finding, got %v", out)
	}
}

func TestRun_UsesRunner(t *testing.T) {
	orig := runner
	defer func() { runner = orig }()
	runner = func(context.Context, string) ([]byte, bool) { return []byte("nothing"), false }
	res, err := New().Run(context.Background(), tool.Args{"target": "img"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("want 1 unsigned finding, got %d", len(res.Findings))
	}
}

func TestCosign_Identity(t *testing.T) {
	if _, ok := tool.Get("cosign"); !ok {
		t.Error("cosign not registered")
	}
}
