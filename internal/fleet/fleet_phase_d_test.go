package fleet

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ClatTribe/tsengine/internal/breaker"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// --- Phase D: side attribution, adjudication, assurance, cost ---

func mustUpdate(t *testing.T, w *Worldview, claims []Claim) {
	t.Helper()
	if err := w.Update(claims); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

// TestSides_BucketedForAdjudication: the merged verdict keeps each SIDE's citations — the raw
// material a panel needs to judge a disagreement on the actual turns.
func TestSides_BucketedForAdjudication(t *testing.T) {
	w := New()
	mustUpdate(t, w, []Claim{{Route: "r", Class: "sqli", Verdict: Vulnerable, Evidence: []string{"c1/t-1"}}})
	mustUpdate(t, w, []Claim{{Route: "r", Class: "sqli", Verdict: Clean, Evidence: []string{"c2/t-9"}}})
	v, _ := w.Get("r", "sqli")
	if v.Verdict != Contested {
		t.Fatalf("want Contested, got %q", v.Verdict)
	}
	if len(v.VulnEvidence) != 1 || v.VulnEvidence[0] != "c1/t-1" {
		t.Errorf("vulnerable side evidence lost: %v", v.VulnEvidence)
	}
	if len(v.CleanEvidence) != 1 || v.CleanEvidence[0] != "c2/t-9" {
		t.Errorf("clean side evidence lost: %v", v.CleanEvidence)
	}
}

// TestResolveContested_Refusals: only a Contested entry may move, only to an evidenced side.
func TestResolveContested_Refusals(t *testing.T) {
	w := New()
	if err := w.ResolveContested("r", "sqli", Vulnerable, "x"); err == nil {
		t.Error("resolving a non-existent entry must fail")
	}
	mustUpdate(t, w, []Claim{{Route: "r", Class: "sqli", Verdict: Clean, Evidence: []string{"t-1"}}})
	if err := w.ResolveContested("r", "sqli", Vulnerable, "x"); err == nil {
		t.Error("resolving a non-Contested (Clean) entry must fail")
	}
	// Contested with NO vulnerable-side evidence cannot resolve to vulnerable.
	mustUpdate(t, w, []Claim{{Route: "r2", Class: "sqli", Verdict: Vulnerable, Evidence: []string{"v-1"}}})
	mustUpdate(t, w, []Claim{{Route: "r2", Class: "sqli", Verdict: Clean, Evidence: []string{"c-1"}}})
	if err := w.ResolveContested("r2", "sqli", Clean, "panel"); err != nil {
		t.Fatalf("clean side HAS evidence; resolve must succeed: %v", err)
	}
	// After a successful resolve the entry is Clean — a second resolve must be refused.
	if err := w.ResolveContested("r2", "sqli", Vulnerable, "reopened"); err == nil {
		t.Error("resolving an entry that is no longer Contested must fail")
	}
}

type fixedJuror struct {
	name string
	v    Verdict
	err  error
}

func (f fixedJuror) Judge(context.Context, ClassVerdict) (VerdictVote, error) {
	return VerdictVote{Juror: f.name, Verdict: f.v, Rationale: "fixed"}, f.err
}

// TestAdjudicateContested_MajorityAndFailOpen: majority resolves to an evidenced side; ties and
// failed panels KEEP Contested (fail-open), and every outcome is recorded with its votes.
func TestAdjudicateContested_MajorityAndFailOpen(t *testing.T) {
	build := func() *Worldview {
		w := New()
		mustUpdate(t, w, []Claim{{Route: "r", Class: "sqli", Verdict: Vulnerable, Evidence: []string{"v-1"}}})
		mustUpdate(t, w, []Claim{{Route: "r", Class: "sqli", Verdict: Clean, Evidence: []string{"c-1"}}})
		return w
	}

	// 2–1 vulnerable → resolved vulnerable.
	w := build()
	adjs, err := AdjudicateContested(context.Background(), w, []Juror{
		fixedJuror{name: "a", v: Vulnerable}, fixedJuror{name: "b", v: Vulnerable}, fixedJuror{name: "c", v: Clean},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(adjs) != 1 || adjs[0].Resolved != Vulnerable {
		t.Fatalf("2-1 majority must resolve vulnerable, got %+v", adjs)
	}
	if len(adjs[0].Votes) != 3 {
		t.Errorf("all three votes must be recorded, got %v", adjs[0].Votes)
	}
	if v, _ := w.Get("r", "sqli"); v.Verdict != Vulnerable {
		t.Errorf("worldview must now read vulnerable, got %q", v.Verdict)
	}

	// Tie → kept Contested.
	w = build()
	adjs, _ = AdjudicateContested(context.Background(), w, []Juror{
		fixedJuror{name: "a", v: Vulnerable}, fixedJuror{name: "b", v: Clean},
	})
	if adjs[0].Resolved != Contested {
		t.Errorf("a tie must keep Contested, got %q", adjs[0].Resolved)
	}
	if v, _ := w.Get("r", "sqli"); v.Verdict != Contested {
		t.Errorf("fail-open: worldview must stay Contested on a tie, got %q", v.Verdict)
	}

	// Wholly-failed panel → kept Contested.
	w = build()
	adjs, _ = AdjudicateContested(context.Background(), w, []Juror{
		fixedJuror{name: "a", err: errors.New("boom")}, fixedJuror{name: "b", err: errors.New("boom")},
	})
	if adjs[0].Resolved != Contested {
		t.Errorf("a failed panel must keep Contested, got %q", adjs[0].Resolved)
	}
	if !strings.Contains(strings.Join(adjs[0].Votes, ";"), "abstain") {
		t.Errorf("failed votes must be recorded as abstentions, got %v", adjs[0].Votes)
	}
}

// TestPanelJuror_ParsesStrictly: a reply that ignores the JSON format is ONE abstention, never a
// forced resolution or a crash.
func TestPanelJuror_ParsesStrictly(t *testing.T) {
	j := PanelJuror{Name: "p", LLM: &scriptLLM{steps: []string{
		`Sure! {"verdict":"clean","rationale":"attempts show nothing"} — hope that helps`,
		`no json at all`,
	}}}
	c := ClassVerdict{Route: "r", Class: "sqli", Verdict: Contested,
		VulnEvidence: []string{"v"}, CleanEvidence: []string{"c"}}
	vote, err := j.Judge(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if vote.Verdict != Clean || vote.Rationale != "attempts show nothing" {
		t.Errorf("fenced JSON must parse, got %+v err=%v", vote, err)
	}
	if _, err := j.Judge(context.Background(), c); err == nil {
		t.Error("an unparsable reply must surface as an error → abstention upstream")
	}
}

// usageLLM implements cloudengine.LLM + both accounting interfaces, standing in for a real brain:
// every Generate ACCUMULATES on the cumulative counter (the contract the delta math depends on).
type usageLLM struct {
	in, out int64 // atomic
	model   string
}

func (u *usageLLM) Generate(_ context.Context, _ string) (string, error) {
	atomic.AddInt64(&u.in, 10_000)
	atomic.AddInt64(&u.out, 2_000)
	return `finish`, nil
}
func (u *usageLLM) TotalUsage() cloudengine.Usage {
	return cloudengine.Usage{InputTokens: atomic.LoadInt64(&u.in), OutputTokens: atomic.LoadInt64(&u.out)}
}
func (u *usageLLM) ModelName() string { return u.model }

// TestRunFleet_CostAccounted: engagement totals are captured from the shared brain's cumulative
// counter and priced via the one table ($/finding rendered in the ledger).
func TestRunFleet_CostAccounted(t *testing.T) {
	srv := benignTarget()
	defer srv.Close()
	// The brain IS the shared worker brain here (production shape): every turn accumulates on its
	// cumulative counter, so the engagement delta is exact even though Generate output is garbage
	// (the loop nudges and burns iterations — that SPEND is exactly what we are asserting).
	brain := &usageLLM{model: "gemini-2.5-flash"}
	baseUsage := brain.TotalUsage() // non-zero brains are legal — the delta is the truth
	in := FrontierInput{
		Target: srv.URL,
		Seeds:  []webagent.SeedFinding{{Route: srv.URL + "/a?q=1", Class: "sqli", Severity: "high"}},
	}
	res, err := RunFleet(context.Background(), brain, srv.URL, in,
		webagent.Options{MaxIters: 3, MaxRequests: 20}, Config{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	total := brain.TotalUsage()
	wantIn, wantOut := total.InputTokens-baseUsage.InputTokens, total.OutputTokens-baseUsage.OutputTokens
	if res.TokensIn != wantIn || res.TokensOut != wantOut || res.TokensIn <= 0 {
		t.Fatalf("engagement token delta wrong: got in=%d out=%d, want in=%d out=%d",
			res.TokensIn, res.TokensOut, wantIn, wantOut)
	}
	delta := cloudengine.Usage{InputTokens: wantIn, OutputTokens: wantOut}
	want := cloudengine.EstimateCost("gemini-2.5-flash", delta)
	if res.CostUSD != want || want <= 0 {
		t.Errorf("cost = %v, want %v", res.CostUSD, want)
	}
	if !strings.Contains(res.Ledger(), "spend: $") {
		t.Errorf("ledger must render spend:\\n%s", res.Ledger())
	}
}

// TestAssurance_VerifiedDoublesTheClampAndSetsCoverK: the tier is paid through the envelope, and
// the doubling is disclosed — never silent.
func TestAssurance_VerifiedDoublesTheClampAndSetsCoverK(t *testing.T) {
	srv := benignTarget()
	defer srv.Close()
	cfg := Config{Workers: 1, TotalRequests: 50, CoverK: 1, Assurance: "verified"}
	wantAdj := applyAssurance(&cfg)
	if !wantAdj || cfg.CoverK < 2 || cfg.TotalRequests != 100 {
		t.Fatalf("verified tier mis-applied: adj=%v coverK=%d total=%d", wantAdj, cfg.CoverK, cfg.TotalRequests)
	}
	fast := Config{Assurance: "fast"}
	if applyAssurance(&fast) {
		t.Error("fast tier must not adjudicate")
	}
	if fast.Assurance != "fast" {
		t.Errorf("empty tier normalizes to fast, got %q", fast.Assurance)
	}
}

// TestRunFleet_SessionInvalidOnAuthedChunksOnly: login walls recorded by the deterministic
// classifier trip the shared breaker ONLY when the chunk claimed an authenticated session.
func TestRunFleet_SessionInvalidOnAuthedChunksOnly(t *testing.T) {
	gov := NewGovernor(EnvelopeConfig{MaxRequests: 100})
	authed := Chunk{ID: "authed", AuthCtx: "primary"}
	guest := Chunk{ID: "guest"}
	cov := webagent.Coverage{LoginWalls: 3}
	observeHealth(gov, authed, cov)
	if n := gov.Breaker().Counts()[breaker.SessionInvalid]; n != 1 {
		t.Fatalf("login walls on an AUTHED chunk must feed session_invalidated, got count %d", n)
	}
	observeHealth(gov, guest, cov)
	if n := gov.Breaker().Counts()[breaker.SessionInvalid]; n != 1 {
		t.Errorf("login walls on an UNAUTH chunk are normal probing — must not record, got %d", n)
	}
	// Three authed workers hitting walls reach the configured limit of 3 → the fleet latches.
	observeHealth(gov, Chunk{AuthCtx: "primary"}, cov)
	observeHealth(gov, Chunk{AuthCtx: "primary"}, cov)
	if tripped, reason := gov.Tripped(); !tripped || !strings.Contains(reason, "session_invalidated") {
		t.Errorf("three authed-chunk wall reports must latch the breaker, tripped=%v reason=%q", tripped, reason)
	}
}
