package orchestrator

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/codelocalize"
	"github.com/ClatTribe/tsengine/internal/codesweep"
	"github.com/ClatTribe/tsengine/internal/envelope"
	"github.com/ClatTribe/tsengine/internal/estimate"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// sweep.go is ADR 0032 D1: the hypothesis sweep joins the repository scan path.
//
// DryRun's scanner-ceiling critique, applied to us: anchors nominate what gets
// hunted, and business-logic/authz flaws are precisely the classes anchors do not
// nominate. internal/codesweep already implements the counter-mechanism —
// deterministic surface enumeration → capped parallel model questions → grounded
// dispose (pattern_match ceiling, counted refusals) — but sat behind the
// on-demand API with zero scan-path callers. This stage wires it in as a
// DOCUMENTED §5.3 DEVIATION: escalation stages are signal-gated; the sweep is
// breadth-gated instead (depth dial + repo-size budget), because its purpose is
// to hunt where signals do not reach. The deviation is stated here rather than
// buried in the program doc.
//
// Budget discipline: question count comes from the depth dial's cap
// (estimate.SweepQuestionCap), and ALL model spend flows through the caller's
// brain — usage accounting happens upstream via cloudengine.UsageReporter deltas,
// so a scan that sweeps reports its own cost honestly.

// SweepConfig enables the repository sweep stage. A zero LLM disables the stage
// entirely (fast depth, or no brain configured → coverage:: disclosure instead of
// a silent skip).
type SweepConfig struct {
	// TokenBudget, when set, is the engagement-wide TOKEN budget for this stage
	// (ADR 0032 D7): consumed post-hoc from brain usage deltas. A breach flips
	// budget semantics once and emits a disclosure — halt-after-breach matches
	// fleet semantics; unknown-usage brains cannot be enforced and say so.
	TokenBudget  *envelope.TokenBudget
	LLM          cloudengine.LLM // required when the stage should run
	Depth        string          // fast | standard | deep ("" → standard)
	MaxQuestions int             // hard cap override; 0 → estimate.SweepQuestionCap(depth)
	// WorkspaceDir is the LOCAL checkout the scan targeted. Repository scans run
	// against a workspace path; remote targets without a local checkout disable
	// the stage with a disclosure (we do not clone here).
	WorkspaceDir string
}

type runOptions struct {
	sweep *SweepConfig
}

// RunOption configures optional RunWithSurface stages. Zero options = byte-for-byte
// today's behavior (the strangler rule every engine change here must satisfy).
type RunOption func(*runOptions)

func WithRepositorySweep(cfg SweepConfig) RunOption {
	return func(ro *runOptions) { ro.sweep = &cfg }
}

// runRepositorySweep executes the hypothesis sweep and appends its findings to
// the final set. Every skip/halt path emits an asset.CoverageRulePrefix finding
// or stderr disclosure — silence is reserved for "complete", never for "didn't
// run" (§10).
func runRepositorySweep(ctx context.Context, cfg SweepConfig, target types.Asset, findings []types.Finding) ([]types.Finding, int64, int64) {
	tr := TraceFrom(ctx)
	now := time.Now().UTC()
	repo := codelocalize.Repo(nil)
	if cfg.WorkspaceDir != "" {
		if r, err := codelocalize.LoadRepo(cfg.WorkspaceDir, codelocalize.LoadOptions{}); err == nil && len(r) > 0 {
			repo = r
		}
	}
	if len(repo) == 0 && strings.TrimSpace(target.Target) != "" &&
		!strings.Contains(target.Target, "://") { // a bare local path works even without the explicit dir
		if r, err := codelocalize.LoadRepo(target.Target, codelocalize.LoadOptions{}); err == nil {
			repo = r
		}
	}
	if len(repo) == 0 {
		return append(findings, sweepSkipFinding(now, "no readable source tree at "+cfg.WorkspaceDir)), 0, 0
	}

	depth := estimate.NormalizeDepth(cfg.Depth)
	capQ := cfg.MaxQuestions
	if capQ <= 0 {
		capQ = estimate.SweepQuestionCap(depth)
	}
	if capQ <= 0 || depth == estimate.DepthFast {
		return append(findings, sweepSkipFinding(now, fmt.Sprintf(
			"codesweep skipped: depth=%s runs deterministic anchors only (the hypothesis sweep is the model-backed stage)", depth))), 0, 0
	}
	_ = capQ

	loc := codelocalize.LLMLocalizer{LLM: cfg.LLM}
	tasks, perr := codesweep.Plan(ctx, loc, repo, codesweep.PlanOptions{MaxTasks: capQ})
	if perr != nil {
		return append(findings, sweepSkipFinding(now, "codesweep plan failed: "+perr.Error())), 0, 0
	}
	var model string
	if mn, ok := cfg.LLM.(cloudengine.ModelNamer); ok {
		model = mn.ModelName()
	}
	var usageBefore cloudengine.Usage
	if ur, ok := cfg.LLM.(cloudengine.UsageReporter); ok {
		usageBefore = ur.TotalUsage()
	}

	tr.Add("sweep", fmt.Sprintf("plan: depth=%s questions=%d", depth, capQ), model, 0, 0, "ok")

	res, err := codesweep.Sweep(ctx, cfg.LLM, repo, tasks, codesweep.SweepOptions{})
	if err != nil {
		tr.Add("sweep-failed", "codesweep error", model, 0, 0, "failed:"+err.Error())
		return append(findings, sweepSkipFinding(now, "codesweep failed: "+err.Error())), 0, 0
	}

	// ADR 0032 D4: adversarial second pass over the sweep's uncovered-class findings.
	// Verify-tier brain (TSENGINE_MODEL_VERIFY override on the same resolution), gated by
	// TSENGINE_SWEEP_DISPROVER=1. Downgrade-only: clean/abstain, never create; abstain and
	// errors fail open. Every downgrade stays in the candidate evidence trail.
	var disprover codesweep.DisproverResult
	if os.Getenv("TSENGINE_SWEEP_DISPROVER") == "1" {
		verify := cloudengine.LLMTiered(cfg.LLM, cloudengine.TierVerify)
		disprover = codesweep.ApplyDisprover(ctx, verify, &res, repo, 400)
		fmt.Fprintf(os.Stderr, "[sweep] disprover: examined=%d downgraded=%d kept=%d errors=%d\n",
			disprover.Examined, disprover.Downgraded, disprover.Kept, disprover.Errors)
	}

	var usedIn, usedOut int64
	if ur, ok := cfg.LLM.(cloudengine.UsageReporter); ok {
		u := ur.TotalUsage()
		usedIn, usedOut = u.InputTokens-usageBefore.InputTokens, u.OutputTokens-usageBefore.OutputTokens
	}
	if cfg.TokenBudget != nil && (usedIn > 0 || usedOut > 0) {
		breached := !cfg.TokenBudget.Spend(usedIn + usedOut)
		tr.Add("sweep-budget", "token budget check", model, usedIn, usedOut,
			map[bool]string{true: "BREACH — budget exceeded", false: "within budget"}[breached])
		if breached {
			res.Candidates = res.Candidates[:0] // budget exhausted: findings stay disclosed via trace, sweep re-runs capped next scan
			fmt.Fprintf(os.Stderr, "[sweep] token budget BREACHED (%d+%d tokens) — candidates withheld, disclosure emitted\n", usedIn, usedOut)
			return append(findings, sweepSkipFinding(now,
				fmt.Sprintf("sweep token budget breached after %d+%d tokens — findings withheld rather than rendered as complete", usedIn, usedOut))), 0, 0
		}
	}
	disposition := fmt.Sprintf("ok: planned=%d ran=%d candidates=%d refused=%d", res.Planned, res.Ran, len(res.Candidates), res.Refused)
	tr.Add("sweep", "hypothesis sweep executed", model, usedIn, usedOut, disposition)
	fmt.Fprintf(os.Stderr, "[sweep] %d question(s) planned, %d ran, %d finding(s), %d refused\n",
		res.Planned, res.Ran, len(res.Candidates), res.Refused)
	out := codesweep.Findings(res, target.Target, now)
	if disprover.Downgraded > 0 {
		out = append(out, sweepSkipFinding(now, fmt.Sprintf(
			"adversarial disprover ran on %d finding(s): %d downgraded, %d kept — downgrades are recorded on their candidates",
			disprover.Examined, disprover.Downgraded, disprover.Kept)))
	}
	return append(findings, out...), 0, 0
}

// sweepSkipFinding states WHY the stage did not run — rendered as nothing, a skip
// reads as a clean estate, which is the exact overclaim this program exists to
// prevent (§10).
func sweepSkipFinding(now time.Time, reason string) types.Finding {
	return types.Finding{
		ID:       "codesweep-skipped",
		RuleID:   "coverage::codesweep-unavailable",
		Tool:     "codesweep",
		Severity: types.SeverityInfo,
		Title:    "Hypothesis sweep did not run",
		Description: "The AI hypothesis sweep was enabled but did NOT run: " + reason +
			". This scan covered deterministic anchors only.",
		DiscoveredAt: now,
		ToolArgs:     map[string]string{"reason": reason},
	}
}
