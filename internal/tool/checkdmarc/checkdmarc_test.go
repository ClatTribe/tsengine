package checkdmarc

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_MissingSPFandDMARC(t *testing.T) {
	blob := []byte(`{"domain":"x.com","spf":{"valid":false,"error":"no record"},"dmarc":{"valid":false,"error":"no record"}}`)
	out := parse(blob, "x.com")
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2 (spf + dmarc)", len(out))
	}
	for _, f := range out {
		if f.Severity != types.SeverityMedium {
			t.Errorf("%s severity = %q, want medium", f.RuleID, f.Severity)
		}
	}
}

func TestParse_DMARCPolicyNone(t *testing.T) {
	blob := []byte(`{"domain":"x.com","spf":{"valid":true},"dmarc":{"valid":true,"tags":{"p":{"value":"none"}}}}`)
	out := parse(blob, "x.com")
	if len(out) != 1 || out[0].RuleID != "checkdmarc::dmarc-policy-none" {
		t.Fatalf("got %v, want a single p=none finding", out)
	}
	if out[0].Severity != types.SeverityLow {
		t.Errorf("p=none severity = %q, want low", out[0].Severity)
	}
}

func TestParse_AllGood(t *testing.T) {
	blob := []byte(`{"domain":"x.com","spf":{"valid":true},"dmarc":{"valid":true,"tags":{"p":{"value":"reject"}}}}`)
	if out := parse(blob, "x.com"); len(out) != 0 {
		t.Errorf("clean posture should yield no findings, got %v", out)
	}
}

func TestCheckDMARC_Identity(t *testing.T) {
	if _, ok := tool.Get("checkdmarc"); !ok {
		t.Error("checkdmarc not registered")
	}
}
