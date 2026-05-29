package scoutsuite

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestStripJSWrapper(t *testing.T) {
	in := []byte("scoutsuite_results =\n{\"services\":{}}\n;")
	got := string(stripJSWrapper(in))
	if got != `{"services":{}}` {
		t.Errorf("stripJSWrapper = %q", got)
	}
}

func TestParse_FlaggedOnly(t *testing.T) {
	blob := []byte(`{"services":{"s3":{"findings":{
	  "s3-bucket-world-readable":{"description":"public bucket","level":"danger","flagged_items":2,"rationale":"why"},
	  "s3-bucket-no-logging":{"description":"no logging","level":"warning","flagged_items":0}
	}}}}`)
	out := parse(blob)
	if len(out) != 1 {
		t.Fatalf("got %d, want 1 (only flagged_items>0)", len(out))
	}
	if out[0].RuleID != "scoutsuite::s3::s3-bucket-world-readable" {
		t.Errorf("RuleID = %q", out[0].RuleID)
	}
	if out[0].Severity != types.SeverityHigh { // danger → high
		t.Errorf("severity = %q, want high", out[0].Severity)
	}
}

func TestScoutSuite_Identity(t *testing.T) {
	if _, ok := tool.Get("scoutsuite"); !ok {
		t.Error("scoutsuite not registered")
	}
}
