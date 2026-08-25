package fleet

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ClatTribe/tsengine/internal/breaker"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// Result is one engagement's output: the worker's UNTOUCHED report plus the worldview built from its
// debrief, and the known-route surface the ledger measures coverage against.
type Result struct {
	Report      *webagent.Report `json:"report"`
	Worldview   *Worldview       `json:"-"` // rendered via Ledger(); the map is unexported
	KnownRoutes []string         `json:"known_routes"`
}

// RunSingle is ADR 0030 Phase A: run ONE worker over the whole authorized surface (today's
// webagent.Investigate, called unchanged), then build the worldview from its findings post-hoc.
//
// STRANGLER GUARANTEE (D2): a 1-chunk, 1-worker fleet changes the worker's output by NOTHING —
// Result.Report IS exactly what webagent.Investigate returns, byte for byte. The worldview is purely
// additive, computed after the fact. TestFleet_SingleWorkerMatchesDirectInvestigate pins this before
// any parallelism ships, so the coordinator can never silently alter an engagement.
func RunSingle(ctx context.Context, llm cloudengine.LLM, cc *webagent.Context, opts webagent.Options) (*Result, error) {
	report, err := webagent.Investigate(ctx, llm, cc, opts)
	if err != nil {
		return nil, err
	}
	w := New()
	// Findings are pre-grounded by webagent's own indicator gate, so every claim carries evidence;
	// Update still enforces evidence-or-refuse as the structural backstop. A finding reaching here
	// without evidence is a contract violation — surfaced, never swallowed.
	if claims := ClaimsFromFindings(report.Findings); len(claims) > 0 {
		if err := w.Update(claims); err != nil {
			return nil, err
		}
	}
	// cc.Routes holds the surface the worker knew (target + seeds + discovered) after the run.
	return &Result{Report: report, Worldview: w, KnownRoutes: CanonicalRoutes(cc.Routes)}, nil
}

// RunFleet is ADR 0030 Phase C: the bounded-parallel coordinator. The plan's chunks are split
// into state-coupled WAVES (PartitionWaves — coupled chunks never share a wave, porting §5.1
// rule 4); within a wave up to cfg.Workers run concurrently via errgroup; waves run strictly in
// order. Every worker is today's webagent.Investigate UNCHANGED (the strangler rule holds per
// chunk), bound by three walls:
//
//   - the ENGAGEMENT ENVELOPE: one shared webagent.Envelope drawn down atomically at send time —
//     N workers can never exceed it regardless of scheduling (D5 vector 2, the absolute wall);
//   - per-worker RESERVATIONS so one greedy chunk cannot starve its peers;
//   - a SHARED latching breaker with health kinds (WAF started blocking / target stopped
//     answering) that halts every remaining wave — degraded conditions invalidate further probes'
//     evidence (a finding absent behind a WAF is not proof the class is absent).
//
// Two deterministic termination guards ride on top: SCHEDULABILITY (a chunk whose declared
// route×class verdicts are already settled at CoverK is skipped — frontier monotonicity, D5) and
// the STALL WATCHDOG (StaleWaves consecutive verdict-free waves halt the run with disclosure).
// Every halt names what did NOT run; nothing is silently dropped (§5.2 rule 5).
//
// Determinism of output: reports and claims are collected per chunk slot and merged in plan
// order after each wave, and the worldview merge itself is order-independent — identical inputs
// yield an identical result regardless of interleaving.
func RunFleet(ctx context.Context, llm cloudengine.LLM, target string, in FrontierInput, baseOpts webagent.Options, cfg Config) (*SequentialResult, error) {
	if in.Target == "" {
		in.Target = target
	}
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.TotalRequests <= 0 {
		cfg.TotalRequests = baseOpts.MaxRequests // serial-equivalent cost by default
	}
	if cfg.CoverK < 1 {
		cfg.CoverK = 1
	}
	if cfg.StaleWaves < 1 {
		cfg.StaleWaves = 2
	}
	wantAdjudication := applyAssurance(&cfg)
	plan := Decompose(in)
	res := &SequentialResult{Plan: plan, Worldview: New()}
	w := res.Worldview
	if wantAdjudication {
		res.Disclosures = append(res.Disclosures, fmt.Sprintf(
			"assurance=verified: CoverK=%d, engagement envelope doubled to %d request(s), contested pairs go to a 3-juror panel — the extra looks are PAID FOR through the same clamp",
			cfg.CoverK, cfg.TotalRequests))
	}

	// Engagement-wide usage accounting (ADR 0030 Phase D): one baseline before the run, one read
	// after. The counter lives on the SHARED brain, so concurrent workers yield an exact total.
	// A brain that does not report usage leaves zeros — rendered as "unknown", never "$0".
	var usageBase cloudengine.Usage
	modelName := ""
	if ur, ok := llm.(cloudengine.UsageReporter); ok {
		usageBase = ur.TotalUsage()
	}
	if mn, ok := llm.(cloudengine.ModelNamer); ok {
		modelName = mn.ModelName()
	}

	gov := cfg.Governor
	if gov == nil {
		gov = NewGovernor(EnvelopeConfig{MaxRequests: cfg.TotalRequests, Window: time.Minute})
	}
	envelope := gov.Envelope()

	waves := PartitionWaves(plan.Chunks)
	res.Waves = len(waves)
	interval := WorkerInterval(baseOpts.MinInterval, cfg.Workers)

	lastVerdicts := -1
	staleWaves := 0
	rawByCanon := map[string]string{} // canonical id → first raw URL that mapped to it (gapfill needs real URLs back)

	for wi, wave := range waves {
		if tripped, reason := gov.Tripped(); tripped {
			res.Disclosures = append(res.Disclosures,
				fmt.Sprintf("fleet halted before wave %d/%d: auto-halt latched (%s); %d chunk(s) not run",
					wi+1, len(waves), reason, countChunks(waves[wi:])))
			break
		}

		// Schedulability filter (frontier monotonicity): settled route×class pairs are skipped,
		// disclosed, and cost zero budget.
		var runnable []Chunk
		for _, c := range wave {
			if settledBy(c, w, cfg.CoverK) {
				res.SkippedChunks = append(res.SkippedChunks, c.ID)
				continue
			}
			runnable = append(runnable, c)
		}
		// Envelope spent? Later chunks disclose rather than spawn workers that cannot send.
		left := envelope.Left()
		if left <= 0 {
			res.Disclosures = append(res.Disclosures,
				fmt.Sprintf("fleet halted before wave %d/%d: engagement request envelope exhausted (%d request(s)); %d chunk(s) not run",
					wi+1, len(waves), cfg.TotalRequests, len(runnable)+countChunks(waves[wi+1:])))
			break
		}
		if len(runnable) == 0 {
			continue // fully settled wave: spent nothing, produced nothing — does not count toward stall
		}

		reports := make([]*webagent.Report, len(runnable))
		claimsPer := make([][]Claim, len(runnable))
		knowns := make([][]string, len(runnable))
		ctxs := make([]*webagent.Context, len(runnable)) // per-worker transcripts for evidence/audit
		reservations := SplitReservations(left, len(runnable))

		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(cfg.Workers)
		for i, c := range runnable {
			i, c := i, c
			g.Go(func() error {
				wllm := llm
				if cfg.NewWorkerLLM != nil {
					wllm = cfg.NewWorkerLLM(c.ID)
				}
				opts := baseOpts
				opts.Seed = append(append([]string{}, baseOpts.Seed...), c.Routes...)
				opts.SeedFindings = c.Seeds
				if reservations[i] > 0 && reservations[i] < opts.MaxRequests {
					opts.MaxRequests = reservations[i]
				}
				opts.MinInterval = interval // fleet-scaled throttle: aggregate ≈ serial cadence
				opts.Envelope = envelope
				opts.SharedBreaker = gov.Breaker()
				cc := &webagent.Context{Target: target}
				rep, err := webagent.Investigate(gctx, wllm, cc, opts)
				if err != nil {
					return err
				}
				reports[i] = rep
				ctxs[i] = cc
				claimsPer[i] = ClaimsFromChunk(c, rep.Findings, cc.History)
				knowns[i] = CanonicalRoutes(cc.Routes)
				observeHealth(gov, c, rep.Coverage)
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return nil, err
		}

		// Merge in plan order (deterministic; the worldview merge is order-independent anyway).
		for _, claims := range claimsPer {
			if len(claims) > 0 {
				if err := w.Update(claims); err != nil {
					return nil, err
				}
			}
		}
		for _, kn := range knowns {
			res.KnownRoutes = append(res.KnownRoutes, kn...)
		}
		res.KnownRoutes = sortUnique(res.KnownRoutes)
		for i := range runnable {
			if reports[i] == nil {
				continue
			}
			for _, raw := range runnable[i].Routes {
				if _, seen := rawByCanon[routeID(raw)]; !seen {
					rawByCanon[routeID(raw)] = raw
				}
			}
		}
		res.Reports = append(res.Reports, reports...)
		res.Contexts = append(res.Contexts, ctxs...)

		// Stall watchdog (D5 vector 6): progress = new verdicts on the ledger.
		n := len(w.Verdicts())
		if n == lastVerdicts {
			staleWaves++
			if staleWaves >= cfg.StaleWaves && wi < len(waves)-1 {
				res.Disclosures = append(res.Disclosures,
					fmt.Sprintf("fleet halted after wave %d/%d: no new verdict(s) across %d consecutive waves — spending without progress (stall watchdog); %d chunk(s) not run",
						wi+1, len(waves), staleWaves, countChunks(waves[wi+1:])))
				break
			}
		} else {
			staleWaves = 0
			lastVerdicts = n
		}
	}

	// GAPFILL (Cloudflare's stage, on our worldview): Inconclusive means "touched but never
	// actually tested" — a request landed, no class payload fired. Those are exactly the areas a
	// hunter touched without covering, so they re-queue as narrow one-pair chunks with a prompt
	// that names what failed before. Bounded twice: by the envelope remainder (a gapfill can
	// never exceed the engagement's authorization) and MaxGapfill. Sequential — these are
	// precision retries, not breadth.
	if cfg.Gapfill {
		type pair struct{ route, class, raw string }
		var pairs []pair
		for _, v := range w.Verdicts() {
			if v.Verdict != Inconclusive {
				continue
			}
			raw, ok := rawByCanon[v.Route]
			if !ok || v.Class == "" {
				continue
			}
			pairs = append(pairs, pair{v.Route, v.Class, raw})
		}
		max := cfg.MaxGapfill
		if max <= 0 {
			max = 12
		}
		dropped := 0
		if len(pairs) > max {
			dropped = len(pairs) - max
			pairs = pairs[:max]
		}
		if len(pairs) > 0 && envelope.Left() > 0 {
			res.Disclosures = append(res.Disclosures,
				fmt.Sprintf("gapfill: %d inconclusive route×class pair(s) re-queued for a narrower second attempt%s",
					len(pairs), map[bool]string{true: fmt.Sprintf(" (%d beyond cap, disclosed)", dropped), false: ""}[dropped > 0]))
			for i, pr := range pairs {
				if tripped, _ := gov.Tripped(); tripped || ctx.Err() != nil || envelope.Left() <= 0 {
					res.Disclosures = append(res.Disclosures,
						fmt.Sprintf("gapfill halted after %d chunk(s): breaker/envelope/ctx", i))
					break
				}
				chunk := Chunk{
					ID: fmt.Sprintf("gap-%03d", i+1), Tier: tierResidual,
					Class: pr.class, Routes: []string{pr.raw},
					Reason: "gapfill: previous pass left this inconclusive — try a DIFFERENT payload class or encoding than the first pass",
				}
				opts := baseOpts
				opts.Seed = append(opts.Seed, chunk.Routes...)
				opts.SeedFindings = []webagent.SeedFinding{{
					Route: chunk.Routes[0], Class: chunk.Class, Tool: "gapfill", Severity: "medium",
					Enrichment: "second pass: previous attempt was inconclusive (touched, not tested)",
				}}
				opts.Envelope = envelope
				opts.SharedBreaker = gov.Breaker()
				cc := &webagent.Context{Target: target}
				wllm := llm
				if cfg.NewWorkerLLM != nil {
					wllm = cfg.NewWorkerLLM(chunk.ID)
				}
				rep, err := webagent.Investigate(ctx, wllm, cc, opts)
				if err != nil {
					return nil, err
				}
				observeHealth(gov, chunk, rep.Coverage)
				if claims := ClaimsFromChunk(chunk, rep.Findings, cc.History); len(claims) > 0 {
					if err := w.Update(claims); err != nil {
						return nil, err
					}
				}
				res.Reports = append(res.Reports, rep)
				res.Contexts = append(res.Contexts, cc)
				res.Plan.Chunks = append(res.Plan.Chunks, chunk)
			}
			res.KnownRoutes = sortUnique(append(res.KnownRoutes, CanonicalRoutes(func() []string {
				var out []string
				for _, pr := range pairs {
					out = append(out, pr.raw)
				}
				return out
			}())...))
		}
	}

	// Phase D: contested pairs go to the majority panel. Fail-open — a deadlock KEEPS Contested and
	// is recorded as its own outcome, never silently dropped.
	if wantAdjudication && llm != nil {
		adjs, err := AdjudicateContested(ctx, w, DefaultPanel(llm))
		if err != nil {
			return nil, err
		}
		res.Adjudications = adjs
	}

	// Engagement totals from the shared brain's cumulative counter.
	if ur, ok := llm.(cloudengine.UsageReporter); ok {
		u := ur.TotalUsage()
		res.TokensIn = u.InputTokens - usageBase.InputTokens
		res.TokensOut = u.OutputTokens - usageBase.OutputTokens
		cacheDelta := u.CacheReadTokens - usageBase.CacheReadTokens
		if modelName != "" {
			res.CostUSD = cloudengine.EstimateCost(modelName, cloudengine.Usage{
				InputTokens: res.TokensIn, OutputTokens: res.TokensOut, CacheReadTokens: cacheDelta,
			})
		}
	}

	return res, nil
}

// settledBy reports whether a chunk's declared work is already done: every declared route×class
// holds a verdict from ≥k independent looks. General chunks (no declared class) are NEVER
// auto-settled — they are exploratory, and guessing "covered" is the absence-as-evidence claim
// this ADR refuses (§10). Contested counts as settled: re-probing it forever is runaway vector 3;
// adjudication (Phase D) owns resolution, and until then Contested renders as Contested.
func settledBy(c Chunk, w *Worldview, k int) bool {
	if c.Class == "" || len(c.Routes) == 0 {
		return false
	}
	for _, r := range c.Routes {
		v, ok := w.Get(routeID(r), c.Class)
		if !ok || v.Workers < k {
			return false
		}
	}
	return true
}

// observeHealth records the grounded degradation signals a finished worker reported into the
// SHARED governor. All derive from real run facts, never inference:
//   - DefensesHit: the WAF/filter signatures the run actually hit;
//   - RequestsSent≥3 with RoutesProbed==0: requests went out, none landed — dead/stonewalling;
//   - LoginWalls>0 on an AUTHED chunk: webauth.IsLoginWall (a deterministic classifier) flagged
//     responses while the session was supposed to be valid — the grounded
//     session_invalidated signal. An UNAUTHED chunk hitting login pages is normal probing and
//     records nothing.
func observeHealth(gov *Governor, c Chunk, cov webagent.Coverage) {
	if len(cov.DefensesHit) > 0 {
		gov.Record(breaker.WAFBlocked)
	}
	if cov.RequestsSent >= 3 && cov.RoutesProbed == 0 {
		gov.Record(breaker.TargetUnhealthy)
	}
	if c.AuthCtx != "" && cov.LoginWalls > 0 {
		gov.Record(breaker.SessionInvalid)
	}
}

func countChunks(waves [][]Chunk) int {
	n := 0
	for _, wv := range waves {
		n += len(wv)
	}
	return n
}
