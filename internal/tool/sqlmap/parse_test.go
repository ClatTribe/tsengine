package sqlmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_ConfirmedInjection(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "vuln.txt"))
	if err != nil {
		t.Fatal(err)
	}
	findings := parse(blob, "http://x/listproducts.php?cat=1")
	if len(findings) != 1 {
		t.Fatalf("got %d findings; want 1 (one vulnerable parameter)", len(findings))
	}
	f := findings[0]
	if f.RuleID != "sqlmap::sqli" || f.Severity != types.SeverityHigh {
		t.Errorf("rule/sev: %q/%q", f.RuleID, f.Severity)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-89" {
		t.Errorf("CWE: %v", f.CWE)
	}
	if f.ToolArgs["parameter"] != "cat" || f.ToolArgs["method"] != "GET" {
		t.Errorf("param/method: %v", f.ToolArgs)
	}
	// Both injection types summarized.
	if !strings.Contains(f.Description, "boolean-based blind") || !strings.Contains(f.Description, "UNION query") {
		t.Errorf("description should list both types: %q", f.Description)
	}
}

func TestParse_NoInjectionNoFindings(t *testing.T) {
	clean := "[INFO] testing connection\n[WARNING] GET parameter 'id' does not seem to be injectable\n[*] ending"
	if got := parse([]byte(clean), "http://x?id=1"); got != nil {
		t.Errorf("clean target should yield no findings; got %v", got)
	}
}

func TestParse_TwoParameters(t *testing.T) {
	two := `Parameter: cat (GET)
    Type: UNION query
    Title: x
Parameter: id (POST)
    Type: boolean-based blind
    Title: y`
	findings := parse([]byte(two), "http://x")
	if len(findings) != 2 {
		t.Fatalf("got %d; want 2 params", len(findings))
	}
	if findings[1].ToolArgs["parameter"] != "id" || findings[1].ToolArgs["method"] != "POST" {
		t.Errorf("second param: %v", findings[1].ToolArgs)
	}
}

func TestSurface(t *testing.T) {
	s := New()
	if s.Name() != "sqlmap" || !s.SandboxExecution() {
		t.Error("surface wrong")
	}
}
