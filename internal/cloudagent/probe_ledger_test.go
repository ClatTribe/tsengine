package cloudagent

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// scriptedProber returns a different result per call and counts LIVE calls, so a test can prove the
// provider was (or was not) actually contacted.
type scriptedProber struct {
	results []ProbeResult
	calls   int
	lastCtx context.Context
}

func (s *scriptedProber) CanPerform(ctx context.Context, _, _, _ string) (ProbeResult, error) {
	s.lastCtx = ctx
	r := ProbeResult{Verdict: VerdictUnknown, Why: "script exhausted"}
	if s.calls < len(s.results) {
		r = s.results[s.calls]
	}
	s.calls++
	return r, nil
}
func (s *scriptedProber) Coverage() string { return "AWS; simulate permission held." }

func probeCtx(p ExploitProber) *Context {
	return &Context{Snap: &cloudgraph.Snapshot{Nodes: map[string]*cloudgraph.Node{}}, Prober: p}
}

func ask(cc *Context, principal, action, resource string) string {
	return tCheckReachable(cc, map[string]any{"principal": principal, "action": action, "resource": resource})
}

// THE coverage property: a DENY is kept, not discarded. The first cut recorded only ALLOWs, so an
// authoritative provider refusal — the strongest negative evidence available — vanished, collapsing
// "we asked and it said no" into "we never asked" (§10). Coverage must show all three answers.
func TestProbeCoverage_KeepsDenialsAndUnknownsNotJustAllows(t *testing.T) {
	p := &scriptedProber{results: []ProbeResult{
		{Verdict: VerdictAllow, ProbedAt: "t1"},
		{Verdict: VerdictDeny, ProbedAt: "t2"},
		{Verdict: VerdictUnknown, Why: "no simulate permission"},
	}}
	cc := probeCtx(p)
	ask(cc, prin, "iam:PassRole", tgt)
	ask(cc, prin, "sts:AssumeRole", tgt)
	ask(cc, prin, "s3:GetObject", "arn:aws:s3:::data")

	cov := cc.ProbeCoverage()
	if cov == nil {
		t.Fatal("coverage must exist once a prober is configured")
	}
	if cov.Tested != 3 || cov.Allowed != 1 || cov.Denied != 1 || cov.Unknown != 1 {
		t.Fatalf("want tested=3 allowed=1 denied=1 unknown=1, got %+v", *cov)
	}
	var sawDeny bool
	for _, r := range cov.Records {
		if r.Verdict == "DENY" && r.Action == "sts:AssumeRole" {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Errorf("the denied move must be recorded by name, got records: %+v", cov.Records)
	}
	if cov.Prober == "" {
		t.Errorf("coverage must carry the prober's own disclosure, else zero probes reads as a clean account")
	}
	// Deterministic order: evidence is persisted and diffed, and Go map order is random.
	first := cc.ProbeCoverage().Records
	for i := 0; i < 5; i++ {
		got := cc.ProbeCoverage().Records
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("probe records must be deterministically ordered; run %d differs at %d", i, j)
			}
		}
	}
}

// "We did not look" and "we looked and found nothing" are different claims. With no prober wired
// there is no tally to report — a zeroed one would read as a clean account.
func TestProbeCoverage_NilWhenNoProberConfigured(t *testing.T) {
	cc := &Context{Snap: &cloudgraph.Snapshot{Nodes: map[string]*cloudgraph.Node{}}}
	if cov := cc.ProbeCoverage(); cov != nil {
		t.Fatalf("no prober must yield NO coverage object, got %+v", *cov)
	}
}

// A DENY must never satisfy ProviderConfirmed. This is load-bearing now that denials share the map
// with allows: without the Allow filter, a path the provider explicitly REFUSED would be stamped
// provider-confirmed — the exact inversion of the evidence.
func TestProviderConfirmed_ADenialIsNeverAConfirmation(t *testing.T) {
	p := &scriptedProber{results: []ProbeResult{{Verdict: VerdictDeny, ProbedAt: "t1"}}}
	cc := probeCtx(p)
	ask(cc, prin, "iam:PassRole", tgt)
	if _, ok := cc.ProviderConfirmed(prin, "iam:PassRole", tgt); ok {
		t.Fatal("a DENY must not read as a provider confirmation")
	}
	if cc.ProbeCoverage().Denied != 1 {
		t.Error("...but it must still be counted as tested-and-denied, not dropped")
	}
}

// An authoritative answer is about a pinned configuration, so re-asking spends the customer's API
// quota and writes another event into their audit trail to learn the same thing.
func TestCheckReachable_AuthoritativeAnswerIsReusedNotReAsked(t *testing.T) {
	p := &scriptedProber{results: []ProbeResult{{Verdict: VerdictAllow, ProbedAt: "t1"}}}
	cc := probeCtx(p)
	ask(cc, prin, "iam:PassRole", tgt)
	got := ask(cc, prin, "iam:PassRole", tgt)
	if p.calls != 1 {
		t.Fatalf("an identical question must not call the provider twice, got %d calls", p.calls)
	}
	if !strings.Contains(got, "ALLOW") || !strings.Contains(got, "reused") {
		t.Errorf("the reused answer must still be the answer, and say it was reused: %s", got)
	}
}

// An UNKNOWN is a NON-answer, often transient (a throttle, one missing permission). Caching it would
// freeze a temporary failure into a permanent one for the rest of the investigation.
func TestCheckReachable_UnknownIsNotCached(t *testing.T) {
	p := &scriptedProber{results: []ProbeResult{
		{Verdict: VerdictUnknown, Why: "throttled"},
		{Verdict: VerdictAllow, ProbedAt: "t2"},
	}}
	cc := probeCtx(p)
	ask(cc, prin, "iam:PassRole", tgt)
	got := ask(cc, prin, "iam:PassRole", tgt)
	if p.calls != 2 {
		t.Fatalf("an UNKNOWN must be re-askable, got %d calls", p.calls)
	}
	if !strings.Contains(got, "ALLOW") {
		t.Errorf("the retry must be able to succeed, got: %s", got)
	}
}

// Read-only is not side-effect-free: each call writes an audit event in the CUSTOMER's account and
// consumes a rate-limited quota, so the loop must be bounded.
func TestCheckReachable_BudgetBoundsLiveProviderCalls(t *testing.T) {
	p := &scriptedProber{results: []ProbeResult{
		{Verdict: VerdictAllow, ProbedAt: "t1"}, {Verdict: VerdictAllow, ProbedAt: "t2"},
		{Verdict: VerdictAllow, ProbedAt: "t3"},
	}}
	cc := probeCtx(p)
	cc.ProbeBudget = 2
	ask(cc, prin, "a:1", tgt)
	ask(cc, prin, "a:2", tgt)
	got := ask(cc, prin, "a:3", tgt)
	if p.calls != 2 {
		t.Fatalf("budget 2 must permit exactly 2 live calls, got %d", p.calls)
	}
	// The refusal must not read as a provider verdict — untested is not denied and not safe.
	if !strings.Contains(got, "budget exhausted") || !strings.Contains(got, "NOT tested") {
		t.Errorf("an exhausted budget must say the move was not tested, got: %s", got)
	}
	if strings.Contains(got, "DENY") {
		t.Errorf("an untested move must never be reported as denied, got: %s", got)
	}
}

// A caller that never heard of ProbeBudget still gets a bound — that is the point of the default.
func TestCheckReachable_UnsetBudgetStillBounded(t *testing.T) {
	p := &scriptedProber{}
	cc := probeCtx(p)
	for i := 0; i < DefaultProbeBudget+25; i++ {
		ask(cc, prin, "a:"+string(rune('A'+i%26))+string(rune('a'+i/26)), tgt)
	}
	if p.calls > DefaultProbeBudget {
		t.Fatalf("an unset budget must still cap live calls at %d, got %d", DefaultProbeBudget, p.calls)
	}
}

// §15: a scan timeout must be able to interrupt a live provider call. The tool signature carries no
// ctx, so before this the probe ran on context.Background() and cancellation could not reach it.
func TestCheckReachable_HonoursTheCallersContext(t *testing.T) {
	p := &scriptedProber{results: []ProbeResult{{Verdict: VerdictAllow, ProbedAt: "t1"}}}
	cc := probeCtx(p)
	ctx, cancel := context.WithCancel(context.Background())
	cc.ctx = ctx
	cancel()
	ask(cc, prin, "iam:PassRole", tgt)
	if p.lastCtx == nil || p.lastCtx.Err() == nil {
		t.Fatal("the caller's (cancelled) context must reach the provider call, not context.Background()")
	}
}
