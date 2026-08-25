package fleet

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ClatTribe/tsengine/internal/breaker"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// governor.go is the engagement ENVELOPE + shared auto-halt of ADR 0030 Phase C (D5 vector 2 and
// vector 4) — ONE type owning both walls so they cannot drift apart:
//
//   - The envelope is the absolute outer wall on requests, drawn down atomically at SEND time by
//     every worker through the very same pool the coordinator reserves from (single ledger: a
//     worker's Take and the coordinator's Reserve consume the same budget). N concurrent workers
//     can never exceed it regardless of scheduling.
//   - The shared breaker latches fleet-wide on egress abuse AND on HEALTH signals (session
//     invalidated, WAF started blocking, target stopped answering) recorded from real run facts.
//     Once tripped, Reserve grants nothing — degraded conditions invalidate further probes'
//     evidence, so spending stops rather than continues into noise.
//
// Per-worker LOCAL caps (SplitReservations) remain the anti-monopoly layer on top; the envelope
// stays the truth about the total.

// EnvelopeConfig sizes a fleet engagement.
type EnvelopeConfig struct {
	// MaxRequests is the ENGAGEMENT-wide authorization. Default wiring passes the serial run's
	// MaxRequests — a fleet costs no more than today's single-agent engagement unless raised.
	MaxRequests int
	// Window is the breaker's sliding window; ≤0 means the whole engagement.
	Window time.Duration
}

// Governor couples the shared envelope and the shared breaker.
type Governor struct {
	env          *webagent.Envelope
	br           *breaker.Breaker
	max          int
	mu           sync.Mutex // guards nothing but keeps future extensions honest; env/br lock themselves
	grantedCache int
}

// NewGovernor builds the fleet's shared governor with conservative health-kind limits:
// egress 3/min (the serial agent's own rule), session-invalidated 3 (repeated login-wall
// evidence), waf_blocked 8, target_unhealthy 3. All latch until Reset — a human resume — never
// auto-clear, because the condition that tripped them does not heal by waiting.
func NewGovernor(c EnvelopeConfig) *Governor {
	if c.MaxRequests < 0 {
		c.MaxRequests = 0
	}
	return &Governor{
		env: webagent.NewEnvelope(c.MaxRequests),
		br: breaker.New(map[breaker.Kind]int{
			breaker.EgressBlocked:   3,
			breaker.SessionInvalid:  3,
			breaker.WAFBlocked:      8,
			breaker.TargetUnhealthy: 3,
		}, c.Window),
		max: c.MaxRequests,
	}
}

// Envelope returns the shared pool workers attach to their Options (nil never: a Governor always
// has one, possibly sized 0 — an engagement authorized to send nothing).
func (g *Governor) Envelope() *webagent.Envelope { return g.env }

// Breaker returns the shared latching breaker for health recording and halt checks.
func (g *Governor) Breaker() *breaker.Breaker { return g.br }

// Reserve atomically draws up to n authorizations from the SAME pool workers spend from, for
// coordinator-side pre-reservation. Returns how many were granted (≤ n). Zero when the breaker
// has latched — a halted fleet spends nothing, even with budget left — or the pool is dry.
func (g *Governor) Reserve(n int) int {
	if n <= 0 {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if tripped, _ := g.br.Tripped(); tripped {
		return 0
	}
	granted := 0
	for i := 0; i < n; i++ {
		if !g.env.Take() {
			break
		}
		granted++
	}
	g.grantedCache += granted
	return granted
}

// Granted reports total authorizations consumed from the pool by ANY path (worker sends and
// coordinator reserves share one ledger).
func (g *Governor) Granted() int { return g.max - g.env.Left() }

// Remaining reports unspent engagement authorizations.
func (g *Governor) Remaining() int { return g.env.Left() }

// Record registers one containment/health signal into the shared breaker. Health kinds ride from
// grounded run facts only (see observeHealth) — never inference.
func (g *Governor) Record(k breaker.Kind) bool { return g.br.Record(k) }

// Tripped reports whether the fleet is halted, and why.
func (g *Governor) Tripped() (bool, string) { return g.br.Tripped() }

// Reset clears the latch — the explicit human resume. Event trail retained for audit.
func (g *Governor) Reset() { g.br.Reset() }

// SplitReservations divides total across n workers — deterministic: earlier workers take the
// remainder so the parts always sum to exactly total. A worker's reservation caps its LOCAL
// MaxRequests (the shared envelope still bounds the sum atomically; reservations stop one greedy
// chunk from monopolizing the engagement before its peers start).
func SplitReservations(total, n int) []int {
	if n <= 0 {
		n = 1
	}
	if total < 0 {
		total = 0
	}
	out := make([]int, n)
	base := total / n
	rem := total % n
	for i := range out {
		out[i] = base
		if i < rem {
			out[i]++
		}
	}
	return out
}

// WorkerInterval scales a serial run's throttle to a fleet of n: each worker waits n× as long
// between sends, so the aggregate cadence ≈ the serial cadence against the shared target.
// Deliberately conservative — it over-throttles idle workers; under-throttling a live target is
// the failure this refuses.
func WorkerInterval(base time.Duration, n int) time.Duration {
	if n < 1 {
		n = 1
	}
	if base < 0 {
		base = 0
	}
	return base * time.Duration(n)
}

// Config bounds a fleet run. Zero/negative fields resolve from env, then defaults.
type Config struct {
	// Workers is the max concurrency WITHIN a wave. 1 = sequential-in-waves (still bounded).
	Workers int // TSENGINE_FLEET_WORKERS
	// TotalRequests is the ENGAGEMENT-wide envelope. Default: baseOpts.MaxRequests — a fleet costs
	// no more requests than today's serial engagement unless raised explicitly.
	TotalRequests int // TSENGINE_FLEET_TOTAL_REQUESTS
	// CoverK is how many independent looks settle a route×class before later chunks skip it
	// (frontier monotonicity, D5: a chunk is schedulable iff executing it reduces a deficit).
	// Contested counts as settled — re-probing it forever is runaway vector 3; adjudication
	// (Phase D) owns resolution.
	CoverK int // TSENGINE_FLEET_COVER_K
	// StaleWaves halts the run when this many consecutive completed waves produced NO new verdicts
	// (the stall watchdog, D5 vector 6 — spending without progress terminates with disclosure).
	StaleWaves int // TSENGINE_FLEET_STALL_WAVES
	// Governor, when set, is used instead of one built from TotalRequests (tests inject a
	// pre-tripped or clock-controlled governor). Nil → built internally.
	Governor *Governor
	// Gapfill runs a SECOND, narrower pass over route×class pairs whose verdict came back
	// Inconclusive (touched but not actually tested) after the main waves — Cloudflare's gapfill
	// stage: hunters flag what they touched without covering; those re-queue for another attempt.
	// Bounded by the SAME envelope remainder (a gapfill can never exceed the engagement's
	// authorization) and capped at MaxGapfill chunks.
	Gapfill bool // TSENGINE_FLEET_GAPFILL
	// MaxGapfill caps gapfill chunks per engagement (default 12).
	MaxGapfill int
	// NewWorkerLLM, when set, builds the brain for EACH worker (keyed by chunk id); nil → every
	// worker shares the caller's llm, which MUST then be safe for concurrent use. The seam exists
	// because a scripted/fake LLM carries per-instance position state — real HTTP-backed brains are
	// stateless and share fine.
	NewWorkerLLM func(chunkID string) cloudengine.LLM
	// Assurance selects the retry/adjudication policy tier (ADR 0030 Phase D):
	//   "" / "fast"     — CoverK=1, no adjudication (pass@1 economics)
	//   "verified"      — CoverK≥2, engagement envelope ×2 (the extra looks are PAID for through
	//                     the same clamp, never free), contested pairs go to a majority panel
	Assurance string // TSENGINE_FLEET_ASSURANCE
}

// applyAssurance normalizes the tier onto the numeric fields and reports whether contested-pair
// adjudication is wanted. The envelope doubling is DISCLOSED by the caller — a policy that spent
// 2× silently would be a cost surprise wearing an assurance label.
func applyAssurance(c *Config) bool {
	switch strings.ToLower(strings.TrimSpace(c.Assurance)) {
	case "verified":
		if c.CoverK < 2 {
			c.CoverK = 2
		}
		c.TotalRequests *= 2
		return true
	default:
		c.Assurance = "fast"
		return false
	}
}

// FromEnv resolves Config against env with serial-equivalent defaults. Unset TSENGINE_FLEET_WORKERS
// means Workers=1 — the fleet machinery runs but never parallelizes (the ADR's "no automatic
// activation" rule: unset env means today's behavior exactly).
func FromEnv(baseMaxRequests int) Config {
	return Config{
		Workers:       envInt("TSENGINE_FLEET_WORKERS", 1),
		TotalRequests: envInt("TSENGINE_FLEET_TOTAL_REQUESTS", baseMaxRequests),
		CoverK:        envInt("TSENGINE_FLEET_COVER_K", 1),
		StaleWaves:    envInt("TSENGINE_FLEET_STALL_WAVES", 2),
		Assurance:     os.Getenv("TSENGINE_FLEET_ASSURANCE"),
		Gapfill:       os.Getenv("TSENGINE_FLEET_GAPFILL") == "1",
		MaxGapfill:    envInt("TSENGINE_FLEET_MAX_GAPFILL", 12),
	}
}

// Health-kind aliases so fleet callers record signals without importing breaker.
const (
	SessionInvalid  = breaker.SessionInvalid
	WAFBlocked      = breaker.WAFBlocked
	TargetUnhealthy = breaker.TargetUnhealthy
)
