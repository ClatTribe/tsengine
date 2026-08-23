package cloudagent

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/agentloop"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Context is the agent's working memory over a pinned cloud snapshot.
type Context struct {
	Snap    *cloudgraph.Snapshot
	Prowler []types.Finding
	MaxHyp  int

	// Bridges are grounded CROSS-SURFACE entry-point hints (G2): footholds discovered on OTHER
	// surfaces (e.g. a leaked AWS key in a code repo) that correlate into THIS cloud account. They
	// tell the cloud specialist where an external attacker already has a foothold so it prioritizes
	// verifying paths FROM that principal/resource — the code→cloud wedge. Each is derived from a real
	// correlation chain (§10); the agent still must confirm every recorded issue in the graph, so a
	// bridge only widens where it LOOKS, it can never fabricate a path.
	Bridges []string

	// Estate is the CROSS-SURFACE graph (internal/estategraph) this cloud account sits inside —
	// code, SaaS, identity, warehouse and cloud in one typed structure. It is what turns the
	// Bridges hints above from prose into something the agent can actually WALK: a bridge said
	// "a leaked key correlates into this account", but the agent could not then ask what else
	// touches that key, or where it came from. estate_context does exactly that.
	//
	// Optional. Nil means the estate graph was not composed for this run, and the tool says so
	// rather than pretending the estate is empty — "we did not look" and "there is nothing" are
	// different answers (§10).
	Estate *estategraph.Graph

	// Live re-reads the account's CURRENT state, so the agent can confirm a config flag its path
	// depends on rather than trusting a snapshot taken before the investigation began. Read-only by
	// construction (see live.go); the credential cap is cloudsafety.SessionPolicy().
	//
	// Optional. Nil means no live path is configured and check_live says exactly that — the same
	// discipline as Estate above, because "the snapshot is unconfirmed" and "the snapshot is
	// current" are different claims (§10).
	Live LiveReader

	// Prober answers "would the provider allow this action?" via the provider's own policy simulator
	// (AWS SimulatePrincipalPolicy / GCP testIamPermissions / Azure checkAccess) WITHOUT performing
	// it — the benign offensive-PROOF primitive (ADR 0024 P1). It upgrades a recorded path from
	// config-possible (our graph says the permission exists) to provider-confirmed (the authority
	// that enforces the policy says the move works). Read-only by construction; the provider is the
	// oracle, so it adds no false-positive surface (§10).
	//
	// Optional. Nil means no dry-run path is configured and check_reachable says exactly that — the
	// same honest degradation as Live and Estate: "we could not prove it" and "it is denied" are
	// different answers.
	Prober ExploitProber

	Issues  []Issue
	Summary string
	Done    bool

	// ProbeBudget bounds how many LIVE provider dry-runs this investigation may spend. A simulate
	// call is read-only but NOT side-effect-free: it writes an audit event in the CUSTOMER's account
	// and consumes a rate-limited quota, so an agent walking a multi-hop graph must not be able to
	// issue an unbounded number of them. Zero means DefaultProbeBudget (a caller that never heard of
	// this field still gets a bound, which is the point); cached answers do not spend it.
	ProbeBudget int

	issueN     int
	calls      int
	probeCalls int
	// probes holds every dry-run outcome of this run, ALLOW and DENY and UNKNOWN alike, keyed by
	// (principal, action, resource). It is both the coverage ledger and the within-run cache.
	probes map[string]ProbeResult
	// ctx is the investigation's context, stashed so tools can honour the caller's cancellation and
	// deadline (§15). Tool handlers take only (cc, args), so without this a scan timeout could not
	// interrupt a live provider call.
	ctx context.Context
}

// Issue is one attack path the LLM determined AND the graph confirmed (grounded).
type Issue struct {
	ID          string   `json:"id"`
	Target      string   `json:"target"`
	TargetName  string   `json:"target_name"`
	Path        []string `json:"path"`
	Severity    string   `json:"severity,omitempty"`
	Rationale   string   `json:"rationale,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	FixKind     string   `json:"fix_kind,omitempty"`
	FixContent  string   `json:"fix_content,omitempty"`
	FixVerified bool     `json:"fix_verified,omitempty"`
	// ProviderConfirmed is true only when EVERY authorization-requiring hop on this path was
	// confirmed ALLOW by the provider's own policy simulator (ADR 0024 P1). It means
	// provider-confirmed AUTHORIZATION — NOT that the path is exploitable, which additionally needs
	// network reachability, credential acquisition, unsupplied session context and the rest of the
	// workflow (see internal/cloudagent/exploitprobe.go for the full ladder).
	ProviderConfirmed bool `json:"provider_confirmed,omitempty"`
	// AuthorizationCoverage is "confirmed/required" hops, so a PARTIAL result stays visible rather
	// than collapsing to a bare false — "3 of 5 hops authorized" and "nothing was checked" are
	// different facts, and rendering them alike is how a partial proof reads as a complete one.
	AuthorizationCoverage string `json:"authorization_coverage,omitempty"`
	// ProofPlan is the per-hop form of the same answer (ADR 0024 P1b): what this path REQUIRES in
	// order to authorize, and what the provider said about each requirement.
	//
	// It exists because the ratio above cannot express a DENIAL. A hop the provider explicitly
	// refused counted exactly like one nobody asked about — both "not confirmed" — so a path the
	// provider had told us was CLOSED rendered as partial evidence that it is OPEN. The plan also
	// separates untested from unknown, which the ratio merged.
	ProofPlan *AuthorizationProofPlan `json:"proof_plan,omitempty"`
}

// Report is the agent's output.
type Report struct {
	Summary string  `json:"summary"`
	Issues  []Issue `json:"issues"`
	Calls   int     `json:"tool_calls"`
	// Probes is what the provider was actually ASKED and what it answered — tested/allowed/denied/
	// unknown plus the per-move records. Nil when no prober was configured, because "we did not
	// look" and "we looked and found nothing" are different claims (§10).
	Probes *ProbeCoverage `json:"probe_coverage,omitempty"`
}

// Options bounds the agent loop.
type Options struct {
	MaxIters int // tool-call turns before the loop is force-closed
	MaxHyp   int // worklist budget for the enumerate_attack_paths prepass tool
	// Ledger, when set, records every ReAct step into the replayable agent decision
	// ledger. Nil-safe (a nil recorder is a no-op).
	Ledger *ledger.Recorder
}

// Investigate runs the LLM-as-brain loop (the VulnAgent shape): the model reads
// the account summary, calls tools to access + assess resources, determines real
// attack paths, records the grounded ones, proposes fixes, and finishes. The LLM
// reasons; the tools answer precisely and refuse ungrounded claims.
func Investigate(ctx context.Context, llm cloudengine.LLM, cc *Context, opts Options) (*Report, error) {
	if opts.MaxIters <= 0 {
		opts.MaxIters = 28
	}
	if opts.MaxHyp <= 0 {
		opts.MaxHyp = 60
	}
	cc.MaxHyp = opts.MaxHyp
	cc.ctx = ctx
	reg := map[string]toolDef{}
	for _, t := range tools() {
		reg[t.name] = t
	}

	var transcript []string
	for i := 0; i < opts.MaxIters && !cc.Done; i++ {
		// A long-horizon agent makes many sequential model calls; a single
		// transient LLM failure must not abort the whole investigation. Retry
		// the turn a few times, then return the partial result we have.
		out, err := agentloop.GenerateWithRetry(ctx, llm, buildPrompt(cc, transcript), 3)
		if err != nil {
			if cc.Summary == "" {
				cc.Summary = fmt.Sprintf("investigation stopped early after a model failure (%v); %d issue(s) confirmed so far", err, len(cc.Issues))
			}
			break
		}
		act, perr := agentloop.ParseAction(out)
		if perr != nil {
			opts.Ledger.Note("reply was not a valid JSON action: " + perr.Error())
			transcript = agentloop.AppendCapped(transcript, "OBSERVATION: your reply was not a valid JSON action ("+perr.Error()+"). Reply with exactly one JSON action.")
			continue
		}
		t, ok := reg[act.Tool]
		if !ok {
			opts.Ledger.Note(fmt.Sprintf("unknown tool %q", act.Tool))
			transcript = agentloop.AppendCapped(transcript, fmt.Sprintf("OBSERVATION: unknown tool %q. Available: %s", act.Tool, toolNames()))
			continue
		}
		cc.calls++
		obs := t.handler(cc, act.Args)
		opts.Ledger.Record(act.Thought, act.Tool, act.Args, obs)
		transcript = agentloop.AppendCapped(transcript, fmt.Sprintf("ACTION %s(%s)\nOBSERVATION: %s", act.Tool, agentloop.CompactArgs(act.Args), obs))
	}
	return &Report{Summary: cc.Summary, Issues: cc.Issues, Calls: cc.calls, Probes: cc.ProbeCoverage()}, nil
}

func toolNames() string {
	var n []string
	for _, t := range tools() {
		n = append(n, t.name)
	}
	return strings.Join(n, ", ")
}
