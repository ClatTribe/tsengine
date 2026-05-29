package hadolint

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_LevelsAndEndpoints(t *testing.T) {
	blob := []byte(`[
	  {"line":3,"code":"DL3002","level":"warning","message":"Last USER should not be root"},
	  {"line":7,"code":"DL3008","level":"error","message":"Pin versions in apt-get install"},
	  {"line":1,"code":"DL3006","level":"info","message":"Always tag the version"}
	]`)
	out := parse(blob, "/workspace/Dockerfile")
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3", len(out))
	}
	if out[0].Endpoint != "/workspace/Dockerfile:3" {
		t.Errorf("endpoint[0] = %q", out[0].Endpoint)
	}
	if out[0].Severity != types.SeverityMedium { // warning → medium
		t.Errorf("warning severity = %q, want medium", out[0].Severity)
	}
	if out[1].Severity != types.SeverityHigh { // error → high
		t.Errorf("error severity = %q, want high", out[1].Severity)
	}
	if out[1].RuleID != "hadolint::DL3008" {
		t.Errorf("RuleID[1] = %q", out[1].RuleID)
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil, "x") != nil {
		t.Error("nil expected")
	}
}

func TestHadolint_Identity(t *testing.T) {
	if _, ok := tool.Get("hadolint"); !ok {
		t.Error("hadolint not registered")
	}
}
