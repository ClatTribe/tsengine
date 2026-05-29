package mobsfscan

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_ResultsAndCWE(t *testing.T) {
	blob := []byte(`{"results":{
	  "android_insecure_webview":{"metadata":{"severity":"WARNING","description":"Insecure WebView","cwe":"CWE-749: Exposed Dangerous Method"},"files":[{"file_path":"app/Main.java","match_lines":[10]}]},
	  "android_hardcoded":{"metadata":{"severity":"ERROR","description":"Hardcoded secret","cwe":"CWE-798"},"files":[{"file_path":"res/strings.xml"}]}
	}}`)
	out := parse(blob)
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2", len(out))
	}
	bySev := map[types.Severity]int{}
	gotCWE := map[string]bool{}
	for _, f := range out {
		bySev[f.Severity]++
		for _, c := range f.CWE {
			gotCWE[c] = true
		}
	}
	if bySev[types.SeverityHigh] != 1 || bySev[types.SeverityMedium] != 1 {
		t.Errorf("severity mapping off: %v", bySev)
	}
	if !gotCWE["CWE-749"] || !gotCWE["CWE-798"] {
		t.Errorf("CWE normalization off: %v", gotCWE)
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil) != nil {
		t.Error("nil expected")
	}
}

func TestMobSFScan_Identity(t *testing.T) {
	if _, ok := tool.Get("mobsfscan"); !ok {
		t.Error("mobsfscan not registered")
	}
}
