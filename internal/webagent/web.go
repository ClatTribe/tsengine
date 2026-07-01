package webagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

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

	History  []Turn    // every request/response (the evidence substrate)
	Findings []Finding // grounded, recorded vulns
	Summary  string
	Done     bool

	ctx   context.Context
	req   *Requester
	turnN int
	findN int
	calls int
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
}

// SeedFinding is a suspected vuln handed to the agent by an L1 scanner
// (nuclei/sqlmap/dalfox). The agent's job is to CONFIRM it (send the request,
// elicit the indicator, record-grounded) rather than rediscover it — "seed from
// scanners, don't start blind" (docs/design/web-agent.md).
type SeedFinding struct {
	Route      string `json:"route"`                // URL to probe (may carry a param marker)
	Class      string `json:"class"`                // suspected class: sqli|xss|open_redirect|path_traversal|command_injection
	Tool       string `json:"tool"`                 // the L1 scanner that raised it (provenance)
	Severity   string `json:"severity,omitempty"`   // the L1 severity (so the agent confirms the worst first)
	Enrichment string `json:"enrichment,omitempty"` // the L1.5 signals (KEV/EPSS/exploit/surface/corrob | compliance)
}

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
	return SeedFinding{
		Route:      f.Endpoint,
		Class:      class,
		Tool:       f.Tool,
		Severity:   string(f.Severity),
		Enrichment: enr,
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
	}
	cc.ctx = ctx
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
	for i := 0; i < opts.MaxIters && !cc.Done; i++ {
		out, err := generateWithRetry(ctx, llm, buildPrompt(cc, transcript), 3)
		if err != nil {
			if cc.Summary == "" {
				cc.Summary = fmt.Sprintf("engagement stopped early after a model failure (%v); %d finding(s) recorded so far", err, len(cc.Findings))
			}
			break
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
		if opts.Progress != nil {
			opts.Progress(cc) // flush partial state so a timeout/SIGKILL can't erase a captured flag
		}
	}
	return &Report{
		Target: cc.Target, Summary: cc.Summary, Findings: cc.Findings,
		Requests: cc.req.Sent(), Calls: cc.calls,
	}, nil
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
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(a) * 2 * time.Second):
			}
		}
		var out string
		if out, err = llm.Generate(ctx, prompt); err == nil {
			return out, nil
		}
	}
	return "", err
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
	if len(entry) > 1800 {
		entry = entry[:1800] + " …(truncated)"
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
