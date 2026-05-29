package orchestrator

import "github.com/ClatTribe/tsengine/internal/asset"

// Dependency classifier — the safety guard for parallel dispatch.
//
// tsengine's fan-out runs dispatches concurrently (errgroup). Today that
// is safe because every wrapped tool is an independent detector. But the
// moment a state-coupled pair lands — auth capture → authed scan, or a
// detector → its verifier — flat concurrency races: the reader may start
// before the writer's side-effect lands. strix shipped exactly this bug
// (unguarded asyncio.gather, proposal §0.2) and had to retrofit a
// classifier (iter-Q4.2 / #576). tsengine lands the guard NOW, before any
// dependent tool exists, so the race is impossible by construction.
//
// partitionWaves layers a dispatch batch into dependency-ordered waves:
// concurrent within a wave, sequential across. An all-independent batch
// (the common case — nuclei, dalfox, httpx fanned across URLs) collapses
// to a single wave, i.e. exactly the pre-W3 behaviour, zero overhead.

// toolDependencies[X] = the set of tool names whose side-effect must
// complete before X may run, IF both appear in the same batch. Keyed by
// the DEPENDENT tool. Conservative: an unlisted pair is independent.
//
// Populated ahead of the tools themselves (W5/W6 auth, L2.5 verifier) so
// the ordering is correct the day those tools are wired.
var toolDependencies = map[string]map[string]bool{
	// Auth/session readers depend on the session writers. (Auth flow
	// lands in W6; the entries are here so the wave order is already
	// right.)
	"scan_idor":           {"seed_auth": true, "scan_auth_flow": true},
	"scan_business_logic": {"seed_auth": true, "scan_auth_flow": true},

	// A verifier re-fires against a finding a detector must have emitted
	// first (L2.5).
	"verify_finding": {
		"nuclei": true, "dalfox": true, "sqlmap": true,
		"scan_idor": true, "scan_auth_flow": true,
	},
}

// partitionWaves splits dispatches into dependency-ordered waves. Each
// tool's wave level = 1 + max(level of its in-batch dependencies), 0 if
// none. Dispatches inherit their tool's level. A cycle (shouldn't occur)
// degrades safely to level 0 (independent).
func partitionWaves(dispatches []asset.Dispatch) [][]asset.Dispatch {
	if len(dispatches) <= 1 {
		return [][]asset.Dispatch{dispatches}
	}

	present := make(map[string]bool, len(dispatches))
	for _, d := range dispatches {
		present[d.Tool.Name()] = true
	}

	level := make(map[string]int)
	var compute func(name string, stack map[string]bool) int
	compute = func(name string, stack map[string]bool) int {
		if l, ok := level[name]; ok {
			return l
		}
		if stack[name] {
			return 0 // cycle guard → treat as independent
		}
		stack[name] = true
		maxDep := -1
		for dep := range toolDependencies[name] {
			if dep != name && present[dep] {
				if dl := compute(dep, stack); dl > maxDep {
					maxDep = dl
				}
			}
		}
		delete(stack, name)
		l := maxDep + 1
		level[name] = l
		return l
	}

	maxLevel := 0
	for _, d := range dispatches {
		if l := compute(d.Tool.Name(), map[string]bool{}); l > maxLevel {
			maxLevel = l
		}
	}

	buckets := make([][]asset.Dispatch, maxLevel+1)
	for _, d := range dispatches {
		l := level[d.Tool.Name()]
		buckets[l] = append(buckets[l], d)
	}

	waves := make([][]asset.Dispatch, 0, len(buckets))
	for _, b := range buckets {
		if len(b) > 0 {
			waves = append(waves, b)
		}
	}
	return waves
}
