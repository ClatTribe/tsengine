package cloudengine

import (
	"os"
	"strings"
)

// modelpolicy.go is ADR 0032 D3: tiered model allocation. Aikido's head-to-head
// (68/89 @ $75 vs Mythos 60/89 @ $157) and Provos's GLM replication both show the
// same thing: cheap brains chasing breadth + a stronger brain verifying beats one
// frontier brain doing everything. The mechanism here is deliberately small:
//
//   - the AMBIENT brain resolves exactly as today (LLMFromEnv / ClientFor);
//   - a tier may override just the MODEL id via TSENGINE_MODEL_<TIER>;
//   - WithModel returns a copy bound to that id — provider, base URL, keys, and
//     all safety wiring are untouched.
//
// Default behavior with no tier env set is byte-for-byte today's single-brain
// setup (asserted by test). A tier whose brain cannot rebind (unknown client
// type) falls back to the default silently — callers that need hard guarantees
// should check TierModel themselves.

type Tier string

const (
	// TierBreadth serves hypothesis sweeps, spec-gen, cweattrib triage — the
	// wide-and-cheap stages where independent attempts matter more than depth.
	TierBreadth Tier = "breadth"
	// TierVerify serves D-agent verification, panel adjudication, final report
	// drafting — the stages where reasoning depth changes outcomes.
	TierVerify Tier = "verify"
)

// TierModel returns the overridden model id for a tier from
// TSENGINE_MODEL_<TIER uppercase> (e.g. TSENGINE_MODEL_BREADTH=deepseek-v4),
// or "" when unset.
func TierModel(tier Tier) string {
	switch tier {
	case TierBreadth:
		return os.Getenv("TSENGINE_MODEL_BREADTH")
	case TierVerify:
		return os.Getenv("TSENGINE_MODEL_VERIFY")
	}
	return ""
}

// LLMTiered returns `base` re-bound to the tier's model when an override is set,
// else `base` unchanged. nil-safe. The override changes ONLY the model id:
// provider, endpoint, and keys stay as resolved — switching providers per tier is
// a config-level decision (point LLM_BASE_URL where you want it), not something
// this seam guesses at.
func LLMTiered(base LLM, tier Tier) LLM {
	m := TierModel(tier)
	if strings.TrimSpace(m) == "" || base == nil {
		return base
	}
	if sw, ok := base.(ModelSwapper); ok {
		if next, did := sw.WithModel(strings.TrimSpace(m)); did {
			return next
		}
	}
	return base
}

// ModelSwapper is implemented by clients that can rebind their model id.
type ModelSwapper interface {
	WithModel(model string) (LLM, bool)
}

var _ = strings.TrimSpace // keep import stable if tiers shrink
