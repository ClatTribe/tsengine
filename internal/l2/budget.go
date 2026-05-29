package l2

import "time"

// Budget bounds an L2 run. strix's founding incident was an unbounded run
// that burned $2.50 for 0 findings (5.8M tokens, cache-missing); every
// dimension here is a hard cap so that can't happen. A zero value means
// "no limit" for that dimension (use Defaults() for sane bounds).
type Budget struct {
	MaxCostUSD     float64       // hard $ cap
	MaxTokens      int           // input+output token cap
	MaxIterations  int           // agent-loop turn cap
	MaxWallClock   time.Duration // wall-clock cap
	MaxIdleTurns   int           // progress watchdog: turns with no progress before force-report

	// running totals
	spentUSD   float64
	spentToks  int
	iterations int
	started    time.Time
	lastProg   int // iteration index of the last progress signal
}

// DefaultBudget returns conservative bounds tuned to keep a scan cheap +
// bounded (the strix acceptance-gate ballpark: ~$0.50–0.80, ~15–20 min).
func DefaultBudget() Budget {
	return Budget{
		MaxCostUSD:    1.00,
		MaxTokens:     2_000_000,
		MaxIterations: 60,
		MaxWallClock:  20 * time.Minute,
		MaxIdleTurns:  6,
	}
}

func (b *Budget) start() {
	if b.started.IsZero() {
		b.started = time.Now()
	}
}

// record folds one turn's usage into the running totals + ticks the
// iteration counter.
func (b *Budget) record(u Usage) {
	b.spentUSD += u.CostUSD
	b.spentToks += u.InputTokens + u.OutputTokens
	b.iterations++
}

// markProgress records that this iteration produced forward progress (a
// finding emitted, a phase advanced) — resets the idle watchdog.
func (b *Budget) markProgress() { b.lastProg = b.iterations }

// idleTurns is how many iterations have passed with no progress.
func (b *Budget) idleTurns() int { return b.iterations - b.lastProg }

// StopReason is why an L2 run ended.
type StopReason string

const (
	StopFinished    StopReason = "finished"      // finish_scan fired
	StopBudgetCost  StopReason = "budget_cost"
	StopBudgetToks  StopReason = "budget_tokens"
	StopMaxIters    StopReason = "max_iterations"
	StopWallClock   StopReason = "wall_clock"
	StopStalled     StopReason = "stalled"        // watchdog: no progress
	StopCancelled   StopReason = "cancelled"      // ctx cancelled
	StopRunning     StopReason = ""               // not stopped yet
)

// exceeded returns the StopReason if any HARD bound is hit, else
// StopRunning. The idle watchdog is handled separately (it force-advances
// to report before stopping), so it's not checked here.
func (b *Budget) exceeded() StopReason {
	if b.MaxCostUSD > 0 && b.spentUSD >= b.MaxCostUSD {
		return StopBudgetCost
	}
	if b.MaxTokens > 0 && b.spentToks >= b.MaxTokens {
		return StopBudgetToks
	}
	if b.MaxIterations > 0 && b.iterations >= b.MaxIterations {
		return StopMaxIters
	}
	if b.MaxWallClock > 0 && !b.started.IsZero() && time.Since(b.started) >= b.MaxWallClock {
		return StopWallClock
	}
	return StopRunning
}

// stalled reports whether the progress watchdog has tripped.
func (b *Budget) stalled() bool {
	return b.MaxIdleTurns > 0 && b.idleTurns() >= b.MaxIdleTurns
}
