package hooks

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func vendFinding(tool, endpoint string, sev types.Severity) types.Finding {
	return types.Finding{ID: "f", RuleID: tool + "::rule", Tool: tool, Endpoint: endpoint, Severity: sev, CWE: []string{"CWE-89"}, Title: "x"}
}

func TestFPFilter_DemotesVendoredSAST(t *testing.T) {
	h := NewFPFilter()
	cases := []string{
		"node_modules/lodash/index.js:42",
		"vendor/github.com/x/y/z.go:10",
		"app/.venv/lib/python3.11/site-packages/foo/bar.py:3",
		"src/third_party/lib.c:99",
	}
	for _, ep := range cases {
		out, audit, keep := h.Apply(vendFinding("semgrep", ep, types.SeverityHigh))
		if !keep {
			t.Errorf("%s should be kept (demoted, not dropped)", ep)
		}
		if out.Severity != types.SeverityLow {
			t.Errorf("%s: severity got %q, want low", ep, out.Severity)
		}
		if len(audit) != 1 || audit[0].Action != "demote" || audit[0].Rule != "fp_filter::vendored-path" {
			t.Errorf("%s: vendored demote not logged: %+v", ep, audit)
		}
	}
}

func TestFPFilter_VendoredGuards(t *testing.T) {
	h := NewFPFilter()

	// SCA / secret tools are NOT demoted even in a vendored path (a vulnerable dependency is
	// still first-party-actionable).
	for _, tool := range []string{"grype", "trivy", "osvscanner", "gitleaks", "trufflehog"} {
		out, _, _ := h.Apply(vendFinding(tool, "vendor/x/y.go:1", types.SeverityHigh))
		if out.Severity != types.SeverityHigh {
			t.Errorf("%s in vendor/ must keep severity, got %q", tool, out.Severity)
		}
	}

	// First-party SAST finding is untouched.
	if out, _, _ := h.Apply(vendFinding("semgrep", "internal/api/handler.go:22", types.SeverityHigh)); out.Severity != types.SeverityHigh {
		t.Errorf("first-party code must keep severity, got %q", out.Severity)
	}

	// The "vendored" substring must NOT match the vendor/ directory rule (word-boundary guard).
	if out, _, _ := h.Apply(vendFinding("semgrep", "internal/vendored_helpers/x.go:1", types.SeverityHigh)); out.Severity != types.SeverityHigh {
		t.Errorf("a 'vendored_helpers' path must not be treated as a vendor dir, got %q", out.Severity)
	}
}
