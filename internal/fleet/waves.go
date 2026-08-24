package fleet

// waves.go partitions the chunk plan into WAVES (ADR 0030 Phase C, porting §5.1 rule 4's
// wave-ordered dispatch to the agent layer). Two rules, both about STATE:
//
//   - ORDERING DEPENDENCY: any chunk that needs the authenticated session (AuthCtx set) must run
//     in a wave STRICTLY AFTER the auth-establishment chunk — there is no session to share before
//     it exists. Chunks with NO auth context are independent of it and may run beside it (their
//     own per-worker sessions are unauthenticated by definition).
//   - MUTUAL EXCLUSION: chunks sharing a StateKey (the reset endpoints / state a differential
//     depends on), or probing the SAME route (by canonical id), never run concurrently — two
//     workers racing one endpoint's state corrupt each other's controls.
//
// Everything else may run concurrently within a wave; waves themselves run strictly in order.
// AuthCtx equality alone does NOT exclude: two authed chunks use per-worker cookie jars (never a
// shared jar — a shared jar poisons bola_diff controls), so they parallelize safely.
//
// Deterministic first-fit over the score-ordered plan (Decompose guarantees the auth chunk is
// first): each chunk joins the FIRST wave satisfying both rules, else opens the next.

// PartitionWaves returns the ordered wave groups.
func PartitionWaves(chunks []Chunk) [][]Chunk {
	waves := make([][]Chunk, 0)
	authWave := -1
	for ci, c := range chunks {
		placed := false
		for wi := range waves {
			if !compatibleWithWave(waves[wi], c) {
				continue
			}
			if c.needsAuth() && wi <= authWave {
				continue // the session does not exist yet at this wave
			}
			waves[wi] = append(waves[wi], c)
			placed = true
			break
		}
		if !placed {
			waves = append(waves, []Chunk{c})
			if c.Tier == tierAuth {
				authWave = len(waves) - 1
			}
		} else if c.Tier == tierAuth {
			// Defensive: Decompose sorts the auth chunk first, but if a caller hands an
			// unsorted plan, record where establishment landed so dependents still order after it.
			authWave = waveOf(waves, ci)
		}
	}
	return waves
}

func (c Chunk) needsAuth() bool { return c.AuthCtx != "" && c.Tier != tierAuth }

func compatibleWithWave(w []Chunk, c Chunk) bool {
	for _, m := range w {
		if excluded(m, c) {
			return false
		}
	}
	return true
}

// excluded is the pairwise mutual-exclusion predicate: same state key, or same route.
func excluded(a, b Chunk) bool {
	if a.StateKey != "" && b.StateKey != "" && a.StateKey == b.StateKey {
		return true
	}
	as := routeSet(a)
	for _, r := range b.Routes {
		if as[routeID(r)] {
			return true
		}
	}
	return false
}

func routeSet(c Chunk) map[string]bool {
	out := make(map[string]bool, len(c.Routes))
	for _, r := range c.Routes {
		out[routeID(r)] = true
	}
	return out
}

func waveOf(waves [][]Chunk, _ int) int {
	for wi, wv := range waves {
		for _, c := range wv {
			if c.Tier == tierAuth {
				return wi
			}
		}
	}
	return -1
}

// WaveCount returns the number of waves in a plan (for tests / telemetry).
func WaveCount(chunks []Chunk) int { return len(PartitionWaves(chunks)) }
