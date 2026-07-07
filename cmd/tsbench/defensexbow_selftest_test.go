//go:build integration

package main

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// defensexbow_selftest_test.go CALIBRATES the defense benchmark on KNOWN ground truth — the way you test a
// grader: positive AND negative controls. It runs the real pipeline (Docker) against a tiny LFI app we fully
// control (fixtures/defense-xbow/selftest-lfi) with three patches whose correct verdict we already know:
//
//	correct.patch   → remediated   (exploit dies, homepage still 200)   — soundness
//	noop.patch      → ineffective  (exploit still leaks the flag)       — doesn't reward a non-fix
//	breaking.patch  → broke_app    (500s everything)                    — the ANTI-SABOTAGE guard works
//
// If the benchmark returns the right verdict for all three, it is calibrated + ungameable by the two cheats
// that matter (break the app / claim a no-op fixed it). Needs Docker; NO LLM and NO XBOW suite (a seeded
// exploit + --patch-file drive it deterministically), and its own compose/image/port (collision-safe).
//
// Run: go test -tags=integration -run DefenseXBOWSelftest ./cmd/tsbench/
func TestDefenseXBOWSelftest_Calibration(t *testing.T) {
	const suite = "../../fixtures/defense-xbow"
	const exploitsDir = "../../fixtures/defense-xbow/exploits"

	benches, err := bench.LoadXBOWSuite(suite)
	if err != nil {
		t.Fatalf("load self-test suite: %v", err)
	}
	var sel bench.XBOWBenchmark
	for _, b := range benches {
		if b.ID == "selftest-lfi" {
			sel = b
		}
	}
	if sel.ID == "" {
		t.Fatal("selftest-lfi fixture not found")
	}

	cases := []struct {
		patch string
		want  string
	}{
		{"../../fixtures/defense-xbow/patches/correct.patch", bench.DefRemediated},
		{"../../fixtures/defense-xbow/patches/noop.patch", bench.DefIneffective},
		{"../../fixtures/defense-xbow/patches/breaking.patch", bench.DefBrokeApp},
	}
	for _, c := range cases {
		c := c
		t.Run(c.want, func(t *testing.T) {
			patchFn, _, perr := resolvePatcher(c.patch)
			if perr != nil {
				t.Fatalf("resolve patch %s: %v", c.patch, perr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
			defer cancel()
			// binary is unused: the seeded exploit is reconfirmed via deterministic replay (no agent, no LLM).
			r := runOneXBOWDefense(ctx, sel, "tsengine-unused", "3m", "", exploitsDir, patchFn)
			if r.Verdict != c.want {
				t.Fatalf("calibration FAILED for %s: got verdict %q (%s), want %q",
					c.patch, r.Verdict, r.Note, c.want)
			}
			t.Logf("OK %s → %s (%s)", c.patch, r.Verdict, r.Note)
		})
	}
}
