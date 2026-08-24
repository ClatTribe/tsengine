package types

import (
	"os"
	"regexp"
	"testing"
)

// evidencerung_all_test.go makes AllEvidenceRungs() authoritative by reading the source's own
// constant declarations. Without it the slice is just a fourth copy of the ladder.
var rungConstRe = regexp.MustCompile(`(?m)^\tRung[A-Za-z]+ EvidenceRung = "([a-z_]+)"`)

func TestAllEvidenceRungsCoversEveryDeclaredConstant(t *testing.T) {
	src, err := os.ReadFile("evidencerung.go")
	if err != nil {
		t.Fatalf("read evidencerung.go: %v", err)
	}
	declared := map[string]bool{}
	for _, m := range rungConstRe.FindAllStringSubmatch(string(src), -1) {
		declared[m[1]] = true
	}
	if len(declared) == 0 {
		t.Fatal("matched no rung constants — the pattern is stale and this guard is inspecting nothing")
	}
	listed := map[string]bool{}
	for _, r := range AllEvidenceRungs() {
		listed[string(r)] = true
	}
	for d := range declared {
		if !listed[d] {
			t.Errorf("rung %q is declared but missing from AllEvidenceRungs(). Every consumer that "+
				"enumerates rungs — including the marketing-ladder guard — reads that slice, so an "+
				"omission here makes those checks silently incomplete.", d)
		}
	}
	for l := range listed {
		if !declared[l] {
			t.Errorf("AllEvidenceRungs() lists %q, which is not a declared constant", l)
		}
	}
}
