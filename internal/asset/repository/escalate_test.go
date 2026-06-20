package repository

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/codeql"
	_ "github.com/ClatTribe/tsengine/internal/tool/govulncheck"
	_ "github.com/ClatTribe/tsengine/internal/tool/mobsfscan"
)

// A Go-project signal (a .go file or a go.mod/go.sum SCA finding) → exactly
// one govulncheck reachability pass; a non-Go repo does not trigger it.
func TestPlanEscalation_GoProjectTriggersGovulncheck(t *testing.T) {
	h := NewHandler()
	fired := func(findings []types.Finding) int {
		n := 0
		for _, d := range h.PlanEscalation(types.Asset{Type: types.AssetRepository, Target: "/r"}, nil, findings) {
			if d.Tool.Name() == "govulncheck" {
				n++
				if d.Args["target"] != WorkspacePath || d.EscalatedFrom == "" {
					t.Errorf("govulncheck dispatch malformed: %+v", d)
				}
			}
		}
		return n
	}
	// .go source findings → fires once (deduped across multiple Go findings).
	if got := fired([]types.Finding{
		{Tool: "semgrep", RuleID: "go.sqli", Endpoint: "internal/db.go"},
		{Tool: "semgrep", RuleID: "go.xss", Endpoint: "internal/web.go"},
	}); got != 1 {
		t.Errorf("Go source findings should fire govulncheck once, got %d", got)
	}
	// SCA finding located in go.mod → fires.
	if got := fired([]types.Finding{{Tool: "trivy", RuleID: "trivy::CVE-2023-1", Endpoint: "go.mod"}}); got != 1 {
		t.Errorf("a go.mod SCA finding should fire govulncheck, got %d", got)
	}
	// Non-Go repo → does not fire.
	if got := fired([]types.Finding{{Tool: "semgrep", RuleID: "py.cmdi", Endpoint: "app/run.py"}}); got != 0 {
		t.Errorf("a non-Go repo must NOT fire govulncheck, got %d", got)
	}
}

// A semgrep injection finding per language → one CodeQL run per language
// (deduped); a mobile-file finding → one mobsfscan.
func TestPlanEscalation_CodeQLPerLanguageAndMobsf(t *testing.T) {
	h := NewHandler()
	findings := []types.Finding{
		{Tool: "semgrep", RuleID: "java.sqli", CWE: []string{"CWE-89"}, Endpoint: "src/Db.java"},
		{Tool: "semgrep", RuleID: "java.xss", CWE: []string{"CWE-79"}, Endpoint: "src/Web.java"}, // same lang → dedup
		{Tool: "semgrep", RuleID: "py.cmdi", CWE: []string{"CWE-78"}, Endpoint: "app/run.py"},
		{Tool: "gitleaks", RuleID: "aws-key", CWE: []string{"CWE-798"}, Endpoint: "src/Other.java"}, // not semgrep → no codeql
		{Tool: "semgrep", RuleID: "mobile", CWE: []string{"CWE-89"}, Endpoint: "app/src/main/AndroidManifest.xml"},
	}
	out := h.PlanEscalation(types.Asset{Type: types.AssetRepository, Target: "/r"}, nil, findings)

	codeqlLangs := map[string]bool{}
	mobsf := 0
	for _, d := range out {
		switch d.Tool.Name() {
		case "codeql":
			codeqlLangs[d.Args["language"].(string)] = true
			if d.Args["target"] != WorkspacePath {
				t.Errorf("codeql target = %v, want workspace", d.Args["target"])
			}
		case "mobsfscan":
			mobsf++
		}
	}
	// java (deduped across .java findings) + python; the AndroidManifest
	// finding has no codeql language but DOES trigger mobsfscan.
	if !codeqlLangs["java"] || !codeqlLangs["python"] {
		t.Errorf("codeql languages = %v, want java+python", codeqlLangs)
	}
	if len(codeqlLangs) != 2 {
		t.Errorf("codeql should run once per language (2), got %d", len(codeqlLangs))
	}
	if mobsf != 1 {
		t.Errorf("mobsfscan should fire once for the mobile finding, got %d", mobsf)
	}
}

func TestPlanEscalation_NoInjectionNoCodeQL(t *testing.T) {
	h := NewHandler()
	findings := []types.Finding{
		{Tool: "semgrep", RuleID: "info", CWE: []string{"CWE-200"}, Endpoint: "src/A.java"},
		{Tool: "trivy", RuleID: "CVE-x", CWE: []string{"CWE-89"}, Endpoint: "pkg@1"}, // not semgrep
	}
	if out := h.PlanEscalation(types.Asset{Type: types.AssetRepository, Target: "/r"}, nil, findings); len(out) != 0 {
		t.Errorf("no semgrep injection → no escalation, got %d", len(out))
	}
}

func TestCodeqlLangForPath(t *testing.T) {
	cases := map[string]string{
		"a/b/X.java": "java", "x.kt": "java", "s.py": "python",
		"f.ts": "javascript", "m.go": "go", "z.txt": "",
	}
	for p, want := range cases {
		if got := codeqlLangForPath(p); got != want {
			t.Errorf("codeqlLangForPath(%q) = %q, want %q", p, got, want)
		}
	}
}
