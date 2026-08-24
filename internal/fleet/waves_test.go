package fleet

import "testing"

// helper: which wave a chunk id landed in.
func waveIndex(waves [][]Chunk, id string) int {
	for w, wv := range waves {
		for _, c := range wv {
			if c.ID == id {
				return w
			}
		}
	}
	return -1
}

func TestPartitionWaves_AllIndependentCollapsesToOneWave(t *testing.T) {
	chunks := []Chunk{
		{ID: "a", Tier: tierSeed, Score: 100},
		{ID: "b", Tier: tierResidual, Score: 50},
		{ID: "c", Tier: tierCrown, Score: 70},
	}
	waves := PartitionWaves(chunks)
	if len(waves) != 1 || len(waves[0]) != 3 {
		t.Fatalf("independent chunks must collapse to ONE wave, got %d waves", len(waves))
	}
}

func TestPartitionWaves_AuthDependencyAndStateCoupling(t *testing.T) {
	chunks := []Chunk{
		{ID: "auth", Tier: tierAuth, Score: 5_000_000, AuthCtx: "primary"},
		{ID: "authed1", Tier: tierSeed, Score: 4_000_100, AuthCtx: "primary"}, // needs auth → wave 1
		{ID: "authed2", Tier: tierSeed, Score: 4_000_050, AuthCtx: "primary"}, // needs auth → wave 1 (parallel with authed1)
		{ID: "indep", Tier: tierResidual, Score: 1_000_000},                   // no auth → wave 0
		{ID: "race1", Tier: tierSeed, Score: 4_000_200, StateKey: "reset-x"},  // coupled
		{ID: "race2", Tier: tierSeed, Score: 4_000_150, StateKey: "reset-x"},  // coupled → different wave from race1
	}
	waves := PartitionWaves(chunks)

	if waveIndex(waves, "auth") != 0 {
		t.Errorf("the auth chunk must be wave 0, got %d", waveIndex(waves, "auth"))
	}
	if waveIndex(waves, "indep") != 0 {
		t.Errorf("an independent chunk must be wave 0, got %d", waveIndex(waves, "indep"))
	}
	if w := waveIndex(waves, "authed1"); w < 1 {
		t.Errorf("an authed chunk must run AFTER the auth chunk (wave ≥1), got %d", w)
	}
	// authed1 and authed2 are per-worker-session independent → SAME wave (parallel).
	if waveIndex(waves, "authed1") != waveIndex(waves, "authed2") {
		t.Errorf("two authed chunks (per-worker sessions) should be parallel, waves %d vs %d",
			waveIndex(waves, "authed1"), waveIndex(waves, "authed2"))
	}
	// STATE-COUPLED chunks must NEVER share a wave.
	if waveIndex(waves, "race1") == waveIndex(waves, "race2") {
		t.Errorf("state-coupled chunks (reset-x) must never share a wave, both in %d", waveIndex(waves, "race1"))
	}
}
