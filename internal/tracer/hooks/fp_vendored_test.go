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

func grypeFinding(pkgType, fixState string, sev types.Severity) types.Finding {
	return types.Finding{ID: "g", RuleID: "grype::CVE-2023-0001", Tool: "grype", Severity: sev,
		CWE: []string{"CWE-79"}, Title: "x", ToolArgs: map[string]string{"pkg_type": pkgType, "fix_state": fixState}}
}

func TestFPFilter_DemotesDistroWontFix(t *testing.T) {
	h := NewFPFilter()

	// An OS/distro package CVE the distro marked wont-fix → demoted to low + logged.
	for _, pt := range []string{"deb", "rpm", "apk"} {
		out, audit, keep := h.Apply(grypeFinding(pt, "wont-fix", types.SeverityHigh))
		if !keep || out.Severity != types.SeverityLow {
			t.Errorf("%s wont-fix should be demoted to low (kept), got sev=%q keep=%v", pt, out.Severity, keep)
		}
		if len(audit) != 1 || audit[0].Rule != "fp_filter::distro-wont-fix" {
			t.Errorf("%s: distro-wont-fix demote not logged: %+v", pt, audit)
		}
	}

	// Guards: a fixable/not-fixed distro CVE, an app-language package, and a non-grype tool are untouched.
	if out, _, _ := h.Apply(grypeFinding("deb", "fixed", types.SeverityHigh)); out.Severity != types.SeverityHigh {
		t.Errorf("a FIXED distro CVE must stay actionable, got %q", out.Severity)
	}
	if out, _, _ := h.Apply(grypeFinding("deb", "not-fixed", types.SeverityHigh)); out.Severity != types.SeverityHigh {
		t.Errorf("a not-fixed (fix may land) CVE must stay actionable, got %q", out.Severity)
	}
	if out, _, _ := h.Apply(grypeFinding("npm", "wont-fix", types.SeverityHigh)); out.Severity != types.SeverityHigh {
		t.Errorf("an APP-dependency wont-fix must stay actionable, got %q", out.Severity)
	}
}
