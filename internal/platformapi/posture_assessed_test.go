package platformapi

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// EVERY posture source must have a door that stamps it.
//
// PostureAssessed exists because these assessors are GROUNDED: a well-managed estate yields zero
// findings, so "assessed and clean" and "never connected" are byte-identical in the findings store.
// A source listed on the posture page with no ingest path that stamps it can only ever read "not
// tested" — the inverse of the false-clean bug, and just as wrong, because a customer who ran the
// check is told they did not.
//
// sspm and osint were both listed nowhere and stamped nowhere while their findings flowed into
// issues, so a hardened GitHub org and an unconnected one produced the same empty posture.
func TestEveryPostureSourceHasAStampingDoor(t *testing.T) {
	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	stamped := map[string]bool{}
	call := regexp.MustCompile(`markPostureAssessed\([^,]+,\s*[^,]+,\s*"([a-z_]+)"`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("cannot read %s (%v) — a guard that cannot see its subject must fail", e.Name(), rerr)
		}
		for _, m := range call.FindAllStringSubmatch(string(src), -1) {
			stamped[m[1]] = true
		}
	}
	// The provenance-driven path stamps from a struct field rather than a literal.
	for _, p := range []findingProvenance{driftProvenance, ciIdentityProvenance, codeSweepProvenance} {
		stamped[p.PostureKind] = true
	}
	if len(stamped) < 3 {
		t.Fatalf("only %d stamping call sites parsed — the pattern broke, not the code", len(stamped))
	}

	for _, s := range postureSources {
		if !stamped[s.Tool] {
			t.Errorf("posture source %q (%s) is shown on the posture page but NOTHING stamps it, so "+
				"it can only ever read 'not tested' — including for a customer who ran it and came "+
				"back clean", s.Tool, s.Label)
		}
	}
}
