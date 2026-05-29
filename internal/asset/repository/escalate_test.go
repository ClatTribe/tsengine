package repository

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/codeql"
	_ "github.com/ClatTribe/tsengine/internal/tool/mobsfscan"
)

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
