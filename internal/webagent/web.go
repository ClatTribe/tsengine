package webagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/breaker"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Context is the agent's working memory for one engagement against one target.
// It is in-process state (not a durable store — that's the platform layer); the
// loop, the tools, and the safety Requester all read/write it.
type Context struct {
	Target   string        // the authorized base URL
	Routes   []string      // known request surface (target + seeded/discovered)
	Seeds    []SeedFinding // suspected L1 findings the agent should confirm
	Defenses []string      // WAF/filter signatures the agent has hit
	// AuthWalls counts responses the deterministic webauth.IsLoginWall classifier flagged — a
	// session that is being shown login forms / auth errors where the agent expected content.
	// The fleet coordinator turns this into the grounded `session_invalidated` health signal for
	// AUTHED chunks (ADR 0030 Phase D); unauthenticated chunks legitimately hit login pages, so
	// they never trip it.
	AuthWalls int

	// Leads is grounded ESTATE CONTEXT: what a route actually reaches, derived from the estate graph.
	// The pentester otherwise sees a flat list of URLs and cannot tell the login form that fronts a PII
	// warehouse from the one that fronts a marketing page — so it spends its budget by shape, not by
	// stakes. This is the web-agent twin of cloudagent.Context.Bridges: the graph tells it WHERE to look
	// hardest, and the deterministic indicators still DISPOSE, so a lead can never fabricate a finding
	// (§10). Empty → today's behaviour exactly; the agent just has less reason to prioritise.
	Leads []EstateLead

	History  []Turn    // every request/response (the evidence substrate)
	Findings []Finding // grounded, recorded vulns
	Summary  string
	Done     bool

	ctx        context.Context
	req        *Requester
	oob        *Collector // lazily started out-of-band interaction collector (blind-vuln proof + exfil)
	dispatcher Dispatcher // optional OSS-specialist dispatch (sqlmap/wpscan/…); nil when not wired
	turnN      int
	findN      int
	calls      int

	// sentReqs remembers the EXACT request (full body + Content-Type) sent for each turn ID, so
	// confirm_exploit can re-fire an upload / large-body proof byte-for-byte. The Turn.Body is
	// display-truncated (512B) and carries no Content-Type, which broke re-firing multipart uploads
	// (XXE-via-SVG-upload, file-upload RCE) — a guessed CT made the server 422 and a real finding got
	// reported "not reproduced". Not serialized (kept out of the transcript/evidence).
	sentReqs map[string]sentReq
}

// sentReq is the exact wire request for a turn, kept in memory for confirm_exploit's byte-for-byte
// re-fire (the recorded Turn.Body is display-truncated and lacks the Content-Type/boundary).
type sentReq struct {
	body        string
	contentType string
}

// turn looks up a request/response by its turn ID (for grounding checks).
func (cc *Context) turn(id string) (Turn, bool) {
	for _, t := range cc.History {
		if t.ID == id {
			return t, true
		}
	}
	return Turn{}, false
}

// Report is the agent's output for one engagement.
type Report struct {
	Target   string    `json:"target"`
	Summary  string    `json:"summary"`
	Findings []Finding `json:"findings"`
	Requests int       `json:"requests_sent"`
	Calls    int       `json:"tool_calls"`
	// Coverage is the honest "what this run did and did NOT reach". Without it a
	// findings list reads as "we tested everything and this is all there was",
	// when the run may have been cut short by the request budget or the
	// iteration cap, throttled by egress denials, or stonewalled by a WAF —
	// §5.2.5's coverage-disclosure ethic applied to the offensive agent.
	Coverage Coverage `json:"coverage"`
}

// Coverage records the run's reach and its limits — every field a real fact
// from run state, never an estimate (§10). A caller (and the VAPT report) can
// tell an empty findings list that means "clean" from one that means "we ran
// out of budget before we finished".
type Coverage struct {
	// StopReason is WHY the loop ended: "completed" (the agent called finish),
	// "iteration_cap", "request_budget", or "model_error". Anything but
	// "completed" means the surface was not fully worked.
	StopReason string `json:"stop_reason"`
	// RoutesKnown is the in-scope surface the agent was aware of; RoutesProbed
	// is how many of them it actually sent a request to. Probed < Known means
	// part of the known surface went untested.
	RoutesKnown  int `json:"routes_known"`
	RoutesProbed int `json:"routes_probed"`
	// RequestBudget is the cap; RequestsSent (mirrored on Report.Requests) how
	// many went out. BudgetExhausted means the cap, not the work, ended the run.
	RequestBudget   int  `json:"request_budget"`
	RequestsSent    int  `json:"requests_sent"`
	BudgetExhausted bool `json:"budget_exhausted"`
	// IterationsUsed / IterationCap: hitting the cap is a truncated run.
	IterationsUsed int `json:"iterations_used"`
	IterationCap   int `json:"iteration_cap"`
	// EgressDenied is the count of outbound requests the egress guard refused
	// (a scoped host that resolved to metadata/loopback). It was counted and
	// read by nothing until now; a non-zero value means probes did not land.
	EgressDenied int `json:"egress_denied"`
	// BreakerTripped: the auto-halt latched (repeated egress blocks), so the run
	// stopped defending itself mid-engagement — coverage is definitely partial.
	BreakerTripped bool `json:"breaker_tripped"`
	// DefensesHit are the WAF/filter signatures the agent ran into; a finding
	// absent behind a WAF is not proof the class is absent.
	DefensesHit []string `json:"defenses_hit,omitempty"`
	// LoginWalls counts responses the deterministic webauth.IsLoginWall classifier flagged during
	// the run (login form served / auth error body / 401). Grounded input for the fleet's
	// session_invalidated health signal on authenticated chunks.
	LoginWalls int `json:"login_walls"`
}

// SeedFinding is a suspected vuln handed to the agent by an L1 scanner
// (nuclei/sqlmap/dalfox). The agent's job is to CONFIRM it (send the request,
// elicit the indicator, record-grounded) rather than rediscover it — "seed from
// scanners, don't start blind" (docs/design/web-agent.md).
// EstateLead tells the pentester what a route LEADS TO, so it prioritises by stakes rather than by the
// shape of the URL. Every field is a grounded fact from the estate graph — a real path the graph holds,
// not a hunch. The agent uses it to choose where to spend its request budget; it never lets a lead stand
// in for proof (a finding still requires the class's deterministic indicator, §10).
type EstateLead struct {
	// Route is the endpoint this lead is about — matched against the agent's known routes.
	Route string `json:"route"`
	// Reaches is the crown jewel at the end of the path, in plain terms ("a table declared to hold PII",
	// "an admin identity"). It is what makes the route worth the budget.
	Reaches string `json:"reaches"`
	// Why is the one-sentence chain: how this route connects to that crown jewel.
	Why string `json:"why"`
	// Evidence is the graph's proof refs for the path, so the lead is auditable rather than asserted.
	Evidence []string `json:"evidence,omitempty"`
}

type SeedFinding struct {
	Route      string `json:"route"`                // URL to probe (may carry a param marker)
	Class      string `json:"class"`                // suspected class: sqli|xss|open_redirect|path_traversal|command_injection
	Tool       string `json:"tool"`                 // the L1 scanner that raised it (provenance)
	Severity   string `json:"severity,omitempty"`   // the L1 severity (so the agent confirms the worst first)
	Enrichment string `json:"enrichment,omitempty"` // the L1.5 signals (KEV/EPSS/exploit/surface/corrob | compliance)
	// ExploitContext is ADR-0019 offensive-face reference material for a CVE-bearing seed — the
	// request SKELETON the agent ADAPTS. Populated by ExploitContextForFinding at seed-build time
	// (like Enrichment), so webagent needs no threat-intel import. Empty on the no-intel path.
	ExploitContext string `json:"exploit_context,omitempty"`
}

// ExploitContextForFinding, when set, returns ADR-0019 offensive-face reference material (a request
// skeleton the agent ADAPTS) for a CVE-bearing finding, else "". It is the webagent half of the shared
// exploit-intel feed (ADR 0021 migration step 1): the SAME resolver pentest.ExploitIntelForFinding uses,
// injected as a func value so webagent gains no new import and the two agents cannot drift. Nil-safe —
// unset leaves the seed's ExploitContext empty and the prompt is byte-identical to today. Grounded (§10):
// the record is input to the PROPOSE step only; the deterministic indicator still DISPOSES, so a wrong or
// stale skeleton widens what the agent TRIES, never what it records.
var ExploitContextForFinding func(f types.Finding) string

// SeedFromFinding maps an ENRICHED L1 finding to a confirmation seed, threading the L1.5 enrichment
// (severity + types.Finding.L15Summary/compliance) so the web agent knows which leads are urgent
// (KEV/high-exploit) before it spends its request budget confirming them. class is the agent's probe
// playbook key (sqli/xss/…), derived by the caller from the finding's CWE/rule.
func SeedFromFinding(f types.Finding, class string) SeedFinding {
	enr := f.L15Summary()
	if c := f.ComplianceSummary(); c != "" {
		if enr != "" {
			enr += " | " + c
		} else {
			enr = c
		}
	}
	exCtx := ""
	if ExploitContextForFinding != nil {
		exCtx = ExploitContextForFinding(f)
	}
	return SeedFinding{
		Route:          f.Endpoint,
		Class:          class,
		Tool:           f.Tool,
		Severity:       string(f.Severity),
		Enrichment:     enr,
		ExploitContext: exCtx,
	}
}

// Options bounds the engagement.
type Options struct {
	MaxIters     int           // tool-call turns before the loop is force-closed
	MaxRequests  int           // hard request cap (the runaway guard)
	MinInterval  time.Duration // throttle between requests (do-no-harm)
	Seed         []string      // optional routes from L1 scanners to start from
	SeedFindings []SeedFinding // optional suspected findings from L1 to CONFIRM
	// Ledger, when set, records every ReAct step (thought / tool / args /
	// observation) into the replayable agent decision ledger. Nil-safe: a nil
	// recorder is a no-op, so the loop calls it unconditionally.
	Ledger *ledger.Recorder
	// Progress, when set, is called after every tool turn with the live Context so the caller
	// can flush partial state (e.g. the transcript) to disk mid-engagement. This makes a long
	// run robust to a hard timeout / SIGKILL: whatever the agent has already observed — including
	// a captured flag — survives even if the loop never reaches a clean finish. Nil-safe.
	Progress func(*Context)
	// Dispatcher, when set, lets the agent hand a specialized job to an OSS tool in the sandbox
	// (sqlmap/wpscan/nuclei/…) via dispatch_oss — the §13 "wrap OSS, don't rebuild" path for
	// blind-SQLi extraction, WordPress CVEs, etc. Nil (standalone host-side runs) → the tool degrades
	// gracefully and says so.
	Dispatcher Dispatcher
	// Envelope, when set, is the ENGAGEMENT-wide request budget shared atomically by every worker in
	// a fleet run (ADR 0030 Phase C). The per-worker MaxRequests stays the worker-local guard; the
	// envelope is the absolute outer wall. Nil → serial behavior, unchanged.
	Envelope *Envelope
	// SharedBreaker, when set, replaces this worker's private auto-halt breaker so one worker's trip
	// latches for the WHOLE fleet (a WAF that started blocking, or a dead target, invalidates every
	// further probe's evidence). The egress callback records into whichever breaker is installed.
	// Nil → a private breaker, exactly today's behavior.
	SharedBreaker *breaker.Breaker
}

// Investigate runs the LLM-as-brain loop against a live target (the cloudagent
// shape, generalized to HTTP). The model reads the surface, sends crafted
// requests, reads the DETERMINISTIC indicators of each response, records the
// grounded findings, confirms them by re-firing, and finishes. The target's
// responses are untrusted data — findings ride on indicators, never on the
// model's reading of attacker-controlled text.
func Investigate(ctx context.Context, llm cloudengine.LLM, cc *Context, opts Options) (*Report, error) {
	if opts.MaxIters <= 0 {
		opts.MaxIters = 30
	}
	if opts.MaxRequests <= 0 {
		opts.MaxRequests = 120
	}
	// Seed routes for the allowlist come from --seed, --target, and any seed
	// findings' routes (the agent must be allowed to probe what L1 flagged).
	allowSeeds := append([]string{}, opts.Seed...)
	for _, sf := range opts.SeedFindings {
		allowSeeds = append(allowSeeds, sf.Route)
	}
	if cc.req == nil {
		cc.req = NewRequester(allowHostsFor(cc.Target, allowSeeds), opts.MaxRequests, opts.MinInterval)
		// Fleet wiring (ADR 0030 Phase C): attach the shared engagement envelope and, when the caller
		// provides one, swap in the SHARED breaker. The egress callback dereferences r.breaker at call
		// time, so the swap is picked up by every later blocked-egress event. Both nil-safe: unset →
		// exactly today's serial behavior.
		cc.req.envelope = opts.Envelope
		if opts.SharedBreaker != nil {
			cc.req.breaker = opts.SharedBreaker
		}
	}
	cc.ctx = ctx
	cc.dispatcher = opts.Dispatcher
	defer func() {
		if cc.oob != nil {
			cc.oob.Stop() // shut the OOB listener at engagement end (best-effort)
		}
	}()
	if cc.Target != "" {
		cc.Routes = appendUniq(cc.Routes, cc.Target)
	}
	for _, s := range opts.Seed {
		cc.Routes = appendUniq(cc.Routes, s)
	}
	if len(opts.SeedFindings) > 0 {
		cc.Seeds = append(cc.Seeds, opts.SeedFindings...)
		for _, sf := range opts.SeedFindings {
			cc.Routes = appendUniq(cc.Routes, sf.Route)
		}
	}

	reg := map[string]toolDef{}
	for _, t := range tools() {
		reg[t.name] = t
	}

	var transcript []string
	stopReason := "iteration_cap" // default: the loop ran out of iterations without the agent finishing
	iters := 0
	for i := 0; i < opts.MaxIters && !cc.Done; i++ {
		iters = i + 1
		out, err := generateWithRetry(ctx, llm, buildPrompt(cc, transcript), 3)
		if err != nil {
			if !isRetryable(err) {
				stopReason = "model_error"
				if cc.Summary == "" {
					cc.Summary = fmt.Sprintf("engagement stopped early after a model failure (%v); %d finding(s) recorded so far", err, len(cc.Findings))
				}
				break
			}
			// Transient throttle window: record it, nudge the turn, and continue
			// rather than killing the whole engagement. The throttle is an
			// orchestration artifact, not a capability miss, and the autopsy
			// must see it as such (Finding 1).
			opts.Ledger.Note(fmt.Sprintf("transient model error (retryable, continuing): %v", err))
			transcript = appendCapped(transcript, fmt.Sprintf("OBSERVATION: model temporarily unavailable (%v) — retrying next turn; engagement continues.", err))
			continue
		}
		act, perr := parseAction(out)
		if perr != nil {
			opts.Ledger.Note("reply was not a valid JSON action: " + perr.Error())
			transcript = appendCapped(transcript, "OBSERVATION: your reply was not a valid JSON action ("+perr.Error()+"). Reply with exactly one JSON action.")
			continue
		}
		t, ok := reg[act.Tool]
		if !ok {
			opts.Ledger.Note(fmt.Sprintf("unknown tool %q", act.Tool))
			transcript = appendCapped(transcript, fmt.Sprintf("OBSERVATION: unknown tool %q. Available: %s", act.Tool, toolNames()))
			continue
		}
		cc.calls++
		obs := t.handler(cc, act.Args)
		opts.Ledger.Record(act.Thought, act.Tool, act.Args, obs)
		transcript = appendCapped(transcript, fmt.Sprintf("ACTION %s(%s)\nOBSERVATION: %s", act.Tool, compactArgs(act.Args), obs))
		if os.Getenv("TSENGINE_AGENT_COMPACT") == "1" {
			transcript = compactTranscript(transcript, cc)
		}
		if opts.Progress != nil {
			opts.Progress(cc) // flush partial state so a timeout/SIGKILL can't erase a captured flag
		}
	}
	if cc.Done {
		stopReason = "completed"
	}
	return &Report{
		Target: cc.Target, Summary: cc.Summary, Findings: cc.Findings,
		Requests: cc.req.Sent(), Calls: cc.calls,
		Coverage: cc.coverage(stopReason, iters, opts.MaxIters),
	}, nil
}

// coverage builds the honest reach-and-limits block from real run state.
func (cc *Context) coverage(stopReason string, iters, iterCap int) Coverage {
	sent := cc.req.Sent()
	tripped, _ := cc.req.Breaker().Tripped()
	cov := Coverage{
		StopReason:      stopReason,
		RoutesKnown:     len(uniqStrings(cc.Routes)),
		RoutesProbed:    len(cc.probedRoutes()),
		RequestBudget:   cc.req.max,
		RequestsSent:    sent,
		BudgetExhausted: (cc.req.max > 0 && sent >= cc.req.max) || (cc.req.envelope != nil && cc.req.envelope.Left() == 0),
		IterationsUsed:  iters,
		IterationCap:    iterCap,
		EgressDenied:    cc.req.Denied(),
		BreakerTripped:  tripped,
		DefensesHit:     uniqStrings(cc.Defenses),
		LoginWalls:      cc.AuthWalls,
	}
	// A request-budget exhaustion is a more specific truth than "iteration_cap":
	// the run stopped because it ran out of requests, not turns.
	if cov.BudgetExhausted && stopReason == "iteration_cap" {
		cov.StopReason = "request_budget"
	}
	return cov
}

// probedRoutes is the set of distinct request URLs the agent actually sent —
// the surface it TESTED, as opposed to the surface it merely KNEW (cc.Routes).
func (cc *Context) probedRoutes() map[string]bool {
	probed := map[string]bool{}
	for _, t := range cc.History {
		if t.URL != "" {
			probed[t.URL] = true
		}
	}
	return probed
}

// uniqStrings returns the distinct non-empty entries, preserving order.
func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// allowHostsFor derives the network allowlist from the target + seed routes. The
// agent may only reach hosts that appear in its authorized surface — never one
// the LLM invents.
func allowHostsFor(target string, seeds []string) []string {
	var hosts []string
	add := func(raw string) {
		if h := hostOf(raw); h != "" {
			hosts = append(hosts, h)
		}
	}
	add(target)
	for _, s := range seeds {
		add(s)
	}
	return hosts
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

// --- the JSON ReAct action (package-local; mirrors cloudagent) ---

type action struct {
	Thought string         `json:"thought"`
	Tool    string         `json:"tool"`
	Args    map[string]any `json:"args"`
}

func parseAction(s string) (action, error) {
	s = stripFences(s)
	if i := strings.IndexByte(s, '{'); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndexByte(s, '}'); j >= 0 {
		s = s[:j+1]
	}
	var a action
	if err := json.Unmarshal([]byte(s), &a); err != nil {
		return a, fmt.Errorf("parse: %v", err)
	}
	if a.Tool == "" {
		var wrap struct {
			Thought string `json:"thought"`
			Action  action `json:"action"`
		}
		if err := json.Unmarshal([]byte(s), &wrap); err == nil && wrap.Action.Tool != "" {
			wrap.Action.Thought = wrap.Thought
			return wrap.Action, nil
		}
		return a, fmt.Errorf("no tool named")
	}
	return a, nil
}

func generateWithRetry(ctx context.Context, llm cloudengine.LLM, prompt string, attempts int) (string, error) {
	var err error
	for a := 0; a < attempts; a++ {
		if a > 0 {
			if err != nil && !isRetryable(err) {
				return "", err // permanent — fail fast, don't burn the batch
			}
			backoff := retryBackoff(a, err)
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
		}
		var out string
		if out, err = llm.Generate(ctx, prompt); err == nil {
			return out, nil
		}
	}
	return "", err
}

// isRetryable reports whether err is worth a retry. Delegates to the shared
// classifier so webagent's throttle behaviour matches every other agent loop.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	// Import avoidance: llmretry lives outside webagent's import graph; inline
	// the classifier's transient-signal set here and keep it in sync via a
	// vet-time assertion (see TestRetryable_MirrorsLlmretry). The alternative —
	// importing llmretry — would add a cross-package dependency for a string test.
	return isTransientLLMError(err)
}

func isTransientLLMError(err error) bool {
	s := strings.ToLower(err.Error())
	for _, sig := range []string{
		"429", "rate limit", "overloaded", "status 500", "status 502", "status 503", "status 504", "status 529",
		"timeout", "i/o timeout", "deadline exceeded", "connection reset", "connection refused", "eof", "temporarily",
	} {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

// retryBackoff computes exponential backoff honoring Retry-After when present.
// Caps at 90s so a single turn cannot consume the whole outer timeout, and that
// wait is charged against ctx (the caller's per-benchmark deadline), not free.
func retryBackoff(attempt int, err error) time.Duration {
	// Honor Retry-After: "retry after 42" or "Retry-After: 30"
	if err != nil {
		lower := strings.ToLower(err.Error())
		if idx := strings.Index(lower, "retry after"); idx >= 0 {
			rest := lower[idx+len("retry after"):]
			rest = strings.TrimLeft(rest, " :\t")
			num := ""
			for _, ch := range rest {
				if ch >= '0' && ch <= '9' {
					num += string(ch)
				} else if num != "" {
					break
				}
			}
			if num != "" {
				secs := 0
				for _, c := range num {
					secs = secs*10 + int(c-'0')
				}
				if secs > 0 && secs <= 120 {
					return time.Duration(secs) * time.Second
				}
			}
		}
	}
	// Exponential: 4s, 8s, 16s … capped at 90s (attempt 1 already waited before, so attempt=1 → 4s)
	shift := attempt + 1
	if shift > 7 { // 2^7 s = 128 s > the 90 s cap; bounding the shift keeps gosec's int→uint check quiet and the arithmetic in range
		shift = 7
	}
	d := time.Duration(1<<shift) * time.Second
	if d > 90*time.Second {
		d = 90 * time.Second
	}
	return d
}

func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}

func compactArgs(args map[string]any) string {
	b, _ := json.Marshal(args)
	if len(b) > 200 {
		b = append(b[:197], "..."...)
	}
	return string(b)
}

func appendCapped(t []string, entry string) []string {
	// Store generously (keep head+tail so a proof at the BOTTOM of a long dump survives); the
	// render step (renderTranscript) compacts OLD entries and shows the LATEST in full.
	if len(entry) > latestEntryCap {
		entry = headTail(entry, latestEntryCap-1024, 1024)
	}
	t = append(t, entry)
	const keep = 24
	if len(t) > keep {
		t = t[len(t)-keep:]
	}
	return t
}

func toolNames() string {
	var n []string
	for _, t := range tools() {
		n = append(n, t.name)
	}
	return strings.Join(n, ", ")
}
