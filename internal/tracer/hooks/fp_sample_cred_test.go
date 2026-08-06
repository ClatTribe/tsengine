package hooks

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func secretFinding(desc string, sev types.Severity) types.Finding {
	return types.Finding{
		ID: "f-1", RuleID: "gitleaks::aws-access-key", Tool: "gitleaks", Severity: sev,
		Title: "AWS access key committed", Description: desc, Endpoint: "config/settings.py:14",
	}
}

// AWS's own documented example key has been in their tutorials for over a decade. Left at critical it
// pages a real on-call for a value that was never a secret — the alert fatigue an AI-SOC exists to remove.
func TestFPFilter_DemotesDocumentedSampleCredential(t *testing.T) {
	got, audit, keep := NewFPFilter().Apply(secretFinding("found key AKIAIOSFODNN7EXAMPLE in source", types.SeverityCritical))

	if !keep {
		t.Fatal("a sample credential must be DEMOTED, never dropped — findings_raw keeps it for the security engineer")
	}
	if got.Severity != types.SeverityInfo {
		t.Fatalf("severity = %s, want info", got.Severity)
	}
	if len(audit) != 1 || audit[0].Rule != "fp_filter::documented-sample-credential" {
		t.Fatalf("the demotion must be logged for recovery via l15_audit_log: %+v", audit)
	}
	if audit[0].FromSeverity != types.SeverityCritical || audit[0].ToSeverity != types.SeverityInfo {
		t.Errorf("audit must record the transition, got %s -> %s", audit[0].FromSeverity, audit[0].ToSeverity)
	}
	if !strings.Contains(audit[0].Reason, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("the reason should name the sample so a reviewer can verify it: %q", audit[0].Reason)
	}
}

// THE SAFETY PROPERTY. This rule suppresses alerts, so it must be exact. A real key must keep its
// severity even when everything around it screams "example" — a loose match here buries a live leak,
// which is far worse than the noise the rule removes.
func TestFPFilter_NeverSuppressesARealKey(t *testing.T) {
	cases := map[string]types.Finding{
		"real key, example filename": func() types.Finding {
			f := secretFinding("found key AKIAQYSTUVWX3EXAMPLE9 in source", types.SeverityCritical)
			f.Endpoint = "docs/examples/sample_config.py:3"
			return f
		}(),
		"real key, 'example' in title": func() types.Finding {
			f := secretFinding("found key AKIA1234567890ABCDEF", types.SeverityCritical)
			f.Title = "example AWS credential committed"
			return f
		}(),
		"near-miss of the documented sample": secretFinding("key AKIAIOSFODNN7EXAMPL0", types.SeverityCritical),
	}
	for name, f := range cases {
		got, audit, keep := NewFPFilter().Apply(f)
		if !keep {
			t.Fatalf("%s: must not be dropped", name)
		}
		if got.Severity != types.SeverityCritical {
			t.Errorf("%s: a real key must keep critical severity, got %s", name, got.Severity)
		}
		for _, a := range audit {
			if a.Rule == "fp_filter::documented-sample-credential" {
				t.Errorf("%s: the sample rule must not fire on a real key", name)
			}
		}
	}
}

// Already-info findings are left alone (no pointless audit churn).
func TestFPFilter_SampleAtInfoIsUntouched(t *testing.T) {
	_, audit, keep := NewFPFilter().Apply(secretFinding("AKIAIOSFODNN7EXAMPLE", types.SeverityInfo))
	if !keep {
		t.Fatal("must not be dropped")
	}
	for _, a := range audit {
		if a.Rule == "fp_filter::documented-sample-credential" {
			t.Error("an already-info finding needs no demotion")
		}
	}
}

func TestDocumentedPublicSample_MatchesAcrossEvidenceFields(t *testing.T) {
	for name, f := range map[string]types.Finding{
		"description": {Description: "leaked AKIAIOSFODNN7EXAMPLE here"},
		"title":       {Title: "AKIAIOSFODNN7EXAMPLE committed"},
		"endpoint":    {Endpoint: "vault://AKIAIOSFODNN7EXAMPLE"},
		"secret key":  {Description: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	} {
		if documentedPublicSample(f) == "" {
			t.Errorf("%s: should match the documented sample", name)
		}
	}
	if documentedPublicSample(types.Finding{Description: "AKIAREALKEY000000000"}) != "" {
		t.Error("a real-looking key must not match")
	}
}
