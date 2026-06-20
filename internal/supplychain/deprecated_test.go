package supplychain

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestScanDeprecated_FlagsAndScores(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "npm", Name: "request", Version: "2.88.2"},  // security-relevant → medium
		{Ecosystem: "npm", Name: "node-uuid", Version: "1.4.8"}, // hygiene → low
		{Ecosystem: "npm", Name: "axios", Version: "1.6.0"},     // maintained → clean
		{Ecosystem: "pypi", Name: "nose", Version: "1.3.7"},     // deprecated → low
	}
	got := map[string]types.Finding{}
	for _, f := range ScanDeprecated(pkgs, DefaultDeprecatedCorpus(), time.Unix(0, 0)) {
		got[f.RuleID] = f
	}
	if len(got) != 3 {
		t.Fatalf("want 3 deprecated findings, got %d: %+v", len(got), got)
	}
	if f := got["deprecated::request"]; f.Severity != types.SeverityMedium {
		t.Errorf("security-relevant deprecation should be medium: %+v", f)
	}
	if f := got["deprecated::node-uuid"]; f.Severity != types.SeverityLow {
		t.Errorf("hygiene deprecation should be low: %+v", f)
	}
	for _, f := range got {
		if f.Tool != "deprecated-packages" || len(f.CWE) == 0 || f.CWE[0] != "CWE-1104" || f.Compliance == nil {
			t.Errorf("deprecated finding not grounded: %+v", f)
		}
		if !strings.Contains(f.Description, "Migrate to") {
			t.Errorf("should recommend a replacement: %q", f.Description)
		}
	}
	if _, bad := got["deprecated::axios"]; bad {
		t.Error("a maintained package must not be flagged")
	}
}
