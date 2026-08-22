package grc_test

// This lives in an EXTERNAL test package on purpose: internal/remediate depends (via
// internal/runner) on internal/grc, so an in-package test importing it would be an import cycle
// — the same constraint that put the shared definition in internal/fixunit.

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/fixunit"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func scaF(id, pkg, installed, fixed string, sev types.Severity) types.Finding {
	return types.Finding{
		ID: id, RuleID: "grype::" + id, Tool: "grype", Severity: sev, Title: "CVE in " + pkg,
		VerificationStatus: "corroborated",
		ToolArgs:           map[string]string{"pkg": pkg, "installed_version": installed, "fixed_version": fixed},
	}
}

// The roadmap's grouping must BE the remediation engine's grouping. If these drift, the plan the
// customer executes and the pull requests the product opens describe different work — which is
// the entire reason internal/fixunit exists.
func TestRoadmapGroupingMatchesRemediationEngine(t *testing.T) {
	f := []types.Finding{
		scaF("f-1", "lodash", "4.17.0", "4.17.21", types.SeverityHigh),
		scaF("f-2", "lodash", "4.17.0", "4.17.5", types.SeverityLow),
		{ID: "f-3", RuleID: "semgrep::sqli", Tool: "semgrep", Severity: types.SeverityHigh, Title: "SQLi"},
	}
	engine := remediate.GroupFindings(f)
	shared := fixunit.GroupBy(f)
	if len(engine) != len(shared) {
		t.Fatalf("group counts differ: engine %d vs shared %d", len(engine), len(shared))
	}
	for i := range engine {
		if engine[i].Key != shared[i].Key || len(engine[i].Findings) != len(shared[i].Findings) {
			t.Errorf("group %d differs: engine %q(%d) vs shared %q(%d)", i,
				engine[i].Key, len(engine[i].Findings), shared[i].Key, len(shared[i].Findings))
		}
	}
	if got := len(grc.BuildRoadmap(f, nil)); got != len(engine) {
		t.Errorf("roadmap produced %d steps for %d fix groups", got, len(engine))
	}
}
