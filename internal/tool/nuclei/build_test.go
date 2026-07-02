package nuclei

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func hasSeq(cli []string, a, b string) bool {
	for i := 0; i < len(cli)-1; i++ {
		if cli[i] == a && cli[i+1] == b {
			return true
		}
	}
	return false
}

// TestAppendOptArgs_ID: the dispatch_oss / replay targeted-CVE arg maps to nuclei -id — the cheap
// known-CVE check (vs -tags cve scanning the whole corpus). Surfaced by the live XBEN-031
// (CVE-2021-41773) dispatch validation.
func TestAppendOptArgs_ID(t *testing.T) {
	cli := appendOptArgs([]string{"-u", "http://t"}, tool.Args{"id": "CVE-2021-41773"})
	if !hasSeq(cli, "-id", "CVE-2021-41773") {
		t.Errorf("id not wired to -id: %v", cli)
	}
}

// TestAppendOptArgs_Empty: no opt args → base untouched (no accidental flags).
func TestAppendOptArgs_Empty(t *testing.T) {
	base := []string{"-u", "http://t", "-jsonl"}
	cli := appendOptArgs(append([]string{}, base...), tool.Args{})
	if len(cli) != len(base) {
		t.Errorf("empty args should not add flags: %v", cli)
	}
}

// TestAppendOptArgs_AllOptional: templates/tags/id/cookie/dast/rate_limit each map to their flag.
func TestAppendOptArgs_AllOptional(t *testing.T) {
	cli := appendOptArgs(nil, tool.Args{
		"templates": "cves/", "tags": "cve", "id": "CVE-2021-41773",
		"cookie": "s=1", "dast": true, "rate_limit": 50,
	})
	for _, fv := range [][2]string{{"-t", "cves/"}, {"-tags", "cve"}, {"-id", "CVE-2021-41773"}, {"-H", "Cookie: s=1"}, {"-rl", "50"}} {
		if !hasSeq(cli, fv[0], fv[1]) {
			t.Errorf("missing %s %s: %v", fv[0], fv[1], cli)
		}
	}
	found := false
	for _, a := range cli {
		if a == "-dast" {
			found = true
		}
	}
	if !found {
		t.Errorf("dast:true should add -dast: %v", cli)
	}
}

// TestKnownArgs_HasID: the arg-contract CI test (§5.2 C4) gates on KnownArgs.
func TestKnownArgs_HasID(t *testing.T) {
	found := false
	for _, k := range New().KnownArgs() {
		if k == "id" {
			found = true
		}
	}
	if !found {
		t.Error("KnownArgs missing 'id'")
	}
}
