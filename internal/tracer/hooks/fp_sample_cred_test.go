package hooks

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestFPFilter_DemotesPublicSampleCredential: a leaked-key finding whose value is AWS's
// documented public example key is a textbook false positive → demoted to info (won't page a
// SOC), audited, while a REAL key and a non-secret finding are untouched.
func TestFPFilter_DemotesPublicSampleCredential(t *testing.T) {
	h := NewFPFilter()
	sample := "AKIA" + "IOSFODNN7EXAMPLE"

	// the documented public sample → demote.
	f := types.Finding{ID: "s1", RuleID: "gitleaks::aws-key", Severity: types.SeverityCritical,
		Title: "AWS access key in docs", Description: "Key " + sample + " in a README code sample"}
	got, audit, keep := h.Apply(f)
	if !keep {
		t.Fatal("sample-credential finding should be kept (demoted), not dropped")
	}
	if got.Severity != types.SeverityInfo {
		t.Errorf("public sample key must be demoted to info, got %s", got.Severity)
	}
	if len(audit) != 1 || audit[0].Action != "demote" || audit[0].Rule != "fp_filter::public-sample-credential" {
		t.Errorf("demotion must be audited, got %+v", audit)
	}

	// a REAL (non-sample) leaked key → untouched.
	real := types.Finding{ID: "s2", RuleID: "gitleaks::aws-key", Severity: types.SeverityHigh,
		Title: "AWS access key", Description: "Key AKIAREALLEAKED1234567 committed"}
	gotReal, _, _ := h.Apply(real)
	if gotReal.Severity != types.SeverityHigh {
		t.Errorf("a real leaked key must NOT be demoted, got %s", gotReal.Severity)
	}

	// a non-secret finding that merely mentions the sample value → untouched (scoped to secret class).
	nonSecret := types.Finding{ID: "s3", RuleID: "nuclei::info-disclosure", Severity: types.SeverityHigh,
		Title: "response mentions " + sample}
	gotNS, _, _ := h.Apply(nonSecret)
	if gotNS.Severity != types.SeverityHigh {
		t.Errorf("a non-secret finding must not be demoted by the sample-credential rule, got %s", gotNS.Severity)
	}
}
