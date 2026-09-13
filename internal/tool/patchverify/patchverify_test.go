package patchverify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A real Go module in a temp dir: the verdict rests on tests that actually ran. Skips only when no
// go toolchain is on PATH — which is the same Unverifiable the tool itself would report.
func fixture(t *testing.T, mainSrc string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain")
	}
	dir := t.TempDir()
	write := func(rel, s string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/fix\n\ngo 1.22\n")
	write("app/sanitize.go", mainSrc)
	write("app/existing_test.go", "package app\n\nimport \"testing\"\n\nfunc TestExisting(t *testing.T) { if Clean(\"ok\") != \"ok\" { t.Fatal(\"clean changed a safe input\") } }\n")
	return dir
}

const vulnerable = "package app\n\nfunc Clean(s string) string { return s }\n"
const fixed = "package app\n\nimport \"strings\"\n\nfunc Clean(s string) string { return strings.ReplaceAll(s, \"'\", \"''\") }\n"
const breaking = "package app\n\nfunc Clean(s string) string { return \"\" }\n" // closes the bug, breaks the existing test
const regression = "package app\n\nimport \"testing\"\n\nfunc TestQuoteIsEscaped(t *testing.T) { if Clean(\"a'b\") == \"a'b\" { t.Fatal(\"quote not escaped\") } }\n"

func TestVerify_VerifiedOnlyWhenRegressionFlipsAndSuiteHolds(t *testing.T) {
	dir := fixture(t, vulnerable)
	v := Verify(context.Background(), dir, map[string]string{"app/sanitize.go": fixed, "app/regression_test.go": regression}, "app/regression_test.go", "")
	if v.Status != Verified {
		t.Fatalf("want verified, got %+v", v)
	}
	if v.RegressionBefore != "fail" || v.RegressionAfter != "pass" || v.SuiteAfter != "pass" || v.Runner != "go" {
		t.Errorf("observations: %+v", v)
	}
}

func TestVerify_NotFixedWhenTheRegressionStillFails(t *testing.T) {
	dir := fixture(t, vulnerable)
	v := Verify(context.Background(), dir, map[string]string{"app/sanitize.go": vulnerable, "app/regression_test.go": regression}, "app/regression_test.go", "")
	if v.Status != NotFixed || v.Output == "" {
		t.Fatalf("want not_fixed with the test output as feedback, got %+v", v)
	}
}

func TestVerify_BrokeSuiteWhenThePatchClosesTheBugByBreakingTheApp(t *testing.T) {
	dir := fixture(t, vulnerable)
	v := Verify(context.Background(), dir, map[string]string{"app/sanitize.go": breaking, "app/regression_test.go": regression}, "app/regression_test.go", "")
	if v.Status != BrokeSuite {
		t.Fatalf("a patch that closes the bug by breaking the app is not a fix, got %+v", v)
	}
}

func TestVerify_VacuousWhenTheRegressionPassesBeforeThePatch(t *testing.T) {
	dir := fixture(t, fixed) // already fixed: the regression passes on the "unpatched" tree
	v := Verify(context.Background(), dir, map[string]string{"app/sanitize.go": fixed, "app/regression_test.go": regression}, "app/regression_test.go", "")
	if v.Status != Vacuous {
		t.Fatalf("a regression that passes before the patch pins nothing, got %+v", v)
	}
}

func TestVerify_UnverifiableIsNamedNeverPassed(t *testing.T) {
	dir := fixture(t, vulnerable)
	// No regression test → nothing can fail-before/pass-after.
	if v := Verify(context.Background(), dir, map[string]string{"app/sanitize.go": fixed}, "", ""); v.Status != Unverifiable || v.Reason == "" {
		t.Errorf("no regression: %+v", v)
	}
	// A JS project: the sandbox has no node, and the tool says so instead of guessing.
	js := t.TempDir()
	_ = os.WriteFile(filepath.Join(js, "package.json"), []byte(`{"name":"x","scripts":{"test":"jest"}}`), 0o644)
	if v := Verify(context.Background(), js, map[string]string{"src/a.js": "x", "src/a.test.js": "y"}, "src/a.test.js", ""); v.Status != Unverifiable || v.Reason == "" {
		t.Errorf("js project: %+v", v)
	}
	// A path that escapes the repository is refused.
	if v := Verify(context.Background(), dir, map[string]string{"../../etc/passwd": "x", "app/regression_test.go": regression}, "app/regression_test.go", ""); v.Status == Verified {
		t.Errorf("an escaping path must not verify: %+v", v)
	}
}

func TestRun_ArgsShapeAndOutputIsJSON(t *testing.T) {
	dir := fixture(t, vulnerable)
	res, err := New().Run(context.Background(), map[string]any{
		"target": dir, "regression": "app/regression_test.go",
		"files": map[string]any{"app/sanitize.go": fixed, "app/regression_test.go": regression},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := res.Output.(string)
	if out == "" || len(res.Findings) != 0 {
		t.Fatalf("the tool reports a JSON verdict and no findings: %+v", res)
	}
	if !contains(out, `"status":"verified"`) {
		t.Errorf("verdict: %s", out)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
