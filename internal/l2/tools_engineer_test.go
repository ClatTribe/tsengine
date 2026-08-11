package l2

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type stubSearch struct{ out string }

func (s stubSearch) Search(context.Context, string) (string, error) { return s.out, nil }

type stubFixer struct {
	id      string
	err     error
	applied bool // must NEVER be set — proposing is not applying
	calls   int
}

func (f *stubFixer) ProposeFix(_ context.Context, _, _ string) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return f.id, nil
}

type stubProver struct{ out string }

func (p stubProver) RequestProof(context.Context, string) (string, error) { return p.out, nil }

type stubVerifier struct{ out string }

func (v stubVerifier) VerifyStatus(context.Context, string) (string, error) { return v.out, nil }

type stubFiler struct{ ref string }

func (f stubFiler) FileTicket(context.Context, string, string) (string, error) { return f.ref, nil }

func call(t *testing.T, c Catalog, name string, args map[string]any) string {
	t.Helper()
	for _, tool := range c {
		if tool.Schema.Name == name {
			res, err := tool.Handler(context.Background(), args, &State{})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			return res.Content
		}
	}
	t.Fatalf("tool %q not in catalogue", name)
	return ""
}

// The catalogue exists to let the agent ACT. If these names drift, the persona silently reverts to an
// analyst that can only read and report.
func TestEngineerTools_ExposesTheActingToolBelt(t *testing.T) {
	c := EngineerTools(stubSearch{}, &stubFixer{}, stubProver{}, stubVerifier{}, stubFiler{})
	want := map[string]bool{"search_estate": false, "propose_fix": false, "request_proof": false,
		"check_fix_status": false, "open_ticket": false}
	for _, tool := range c {
		if _, ok := want[tool.Schema.Name]; ok {
			want[tool.Schema.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("%s missing — the agent cannot do that part of the job", name)
		}
	}
}

// THE safety property that makes autonomy acceptable: proposing is not applying. The agent gains a
// voice, not authority — the tool queues a change and a human decides.
func TestProposeFix_QueuesForApprovalAndNeverApplies(t *testing.T) {
	f := &stubFixer{id: "act-42"}
	c := EngineerTools(nil, f, nil, nil, nil)

	got := call(t, c, "propose_fix", map[string]any{"finding_id": "f-1", "rationale": "parameterise the query"})

	if f.applied {
		t.Fatal("propose_fix applied a change — it must only queue one")
	}
	if !strings.Contains(got, "act-42") {
		t.Errorf("result should name the queued action so the agent can refer to it, got %q", got)
	}
	if !strings.Contains(strings.ToLower(got), "not applied") {
		t.Errorf("the result must tell the agent plainly that nothing was applied, got %q", got)
	}
}

// A refusal is usually grounding working (an unknown finding id). It must read as a refusal, so the
// agent stops rather than retrying blindly — and must not look like success.
func TestProposeFix_SurfacesARefusalHonestly(t *testing.T) {
	c := EngineerTools(nil, &stubFixer{err: errors.New("no finding f-9")}, nil, nil, nil)
	got := call(t, c, "propose_fix", map[string]any{"finding_id": "f-9"})
	if !strings.Contains(got, "Could not propose") || !strings.Contains(got, "no finding f-9") {
		t.Errorf("a refusal must say why, got %q", got)
	}
}

// An unwired capability must SAY it is unavailable. The dangerous failure is an agent that believes it
// filed a ticket in a deployment with no ticketing connector.
func TestEngineerTools_UnwiredCapabilitiesAdmitIt(t *testing.T) {
	c := EngineerTools(nil, nil, nil, nil, nil)
	for _, tc := range []struct{ tool, arg string }{
		{"search_estate", "query"}, {"propose_fix", "finding_id"},
		{"request_proof", "finding_id"}, {"check_fix_status", "action_id"}, {"open_ticket", "title"},
	} {
		got := call(t, c, tc.tool, map[string]any{tc.arg: "x"})
		low := strings.ToLower(got)
		if !strings.Contains(low, "not available") && !strings.Contains(low, "not connected") {
			t.Errorf("%s with no backing said %q — it must admit the capability is missing", tc.tool, got)
		}
	}
}

// Missing arguments are a model mistake, not a crash. The tool should correct it and let the agent retry.
func TestEngineerTools_MissingArgsAreCorrectedNotFatal(t *testing.T) {
	c := EngineerTools(stubSearch{out: "x"}, &stubFixer{id: "a"}, stubProver{}, stubVerifier{}, stubFiler{})
	if got := call(t, c, "propose_fix", map[string]any{}); !strings.Contains(got, "needs a finding_id") {
		t.Errorf("got %q, want a corrective message", got)
	}
	if got := call(t, c, "search_estate", map[string]any{"query": "   "}); !strings.Contains(got, "needs a query") {
		t.Errorf("whitespace-only args should be treated as missing, got %q", got)
	}
}

// request_proof must never let a failed exploit read as an all-clear — the asymmetry the whole
// doubt→prove edge rests on.
func TestRequestProof_PassesTheProverVerdictThrough(t *testing.T) {
	c := EngineerTools(nil, nil, stubProver{out: "no working exploit found — NOT evidence of a false positive"}, nil, nil)
	got := call(t, c, "request_proof", map[string]any{"finding_id": "f-1"})
	if !strings.Contains(got, "NOT evidence") {
		t.Errorf("the prover's caveat must reach the agent verbatim, got %q", got)
	}
}
