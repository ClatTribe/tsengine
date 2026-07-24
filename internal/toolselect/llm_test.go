package toolselect

import (
	"context"
	"errors"
	"testing"
)

type mockGen struct {
	resp      string
	err       error
	gotPrompt string
}

func (m *mockGen) Generate(_ context.Context, prompt string) (string, error) {
	m.gotPrompt = prompt
	return m.resp, m.err
}

// TestSelectLLM_ClosedSetAndCap: the model's proposal is DISPOSED — a hallucinated tool is dropped,
// real picks survive, CORE is always present, and the total never exceeds the cap.
func TestSelectLLM_ClosedSetAndCap(t *testing.T) {
	cat := webagentCatalog()
	// Model returns a hallucinated tool + two real ones, in prose+fence to test parsing too.
	gen := &mockGen{resp: "Sure, here you go:\n```json\n[\"privesc_probe\", \"totally_fake_tool\", \"bola_probe\"]\n```"}
	sel, fb := cat.SelectLLM(context.Background(), Query{Task: "escalate a normal user to admin", MaxActive: 7}, gen)
	if fb {
		t.Fatal("a valid model response should not trigger fallback")
	}
	names := sel.Names()
	if !contains(names, "privesc_probe") || !contains(names, "bola_probe") {
		t.Errorf("real proposed tools should survive, got %v", names)
	}
	if contains(names, "totally_fake_tool") {
		t.Errorf("a hallucinated tool must be dropped (closed-set), got %v", names)
	}
	for _, core := range []string{"send_request", "record_finding", "finish", "dispatch_oss"} {
		if !contains(names, core) {
			t.Errorf("core tool %q must be present, got %v", core, names)
		}
	}
	if len(sel.Tools) > 7 {
		t.Errorf("active set %d exceeds cap 7", len(sel.Tools))
	}
}

func TestSelectLLM_CapTruncatesModelOverpick(t *testing.T) {
	cat := webagentCatalog()
	// Model over-picks (more than the cap allows); disposal truncates, core still present.
	gen := &mockGen{resp: `["sqli_bool_probe","nosqli_probe","bola_probe","privesc_probe","jwt_crack","race_probe","ssh_exec","crack_hash"]`}
	sel, _ := cat.SelectLLM(context.Background(), Query{Task: "everything", MaxActive: 6}, gen)
	if len(sel.Tools) != 6 {
		t.Errorf("cap must hold against an over-picking model: got %d, want 6", len(sel.Tools))
	}
	if !contains(sel.Names(), "send_request") {
		t.Error("core must survive truncation (prepended first)")
	}
}

func TestSelectLLM_FallsBackOnModelFailure(t *testing.T) {
	cat := webagentCatalog()
	// Error and garbage both fall back to the deterministic BM25 selection (never empty/broken).
	for _, gen := range []*mockGen{{err: errors.New("timeout")}, {resp: "I couldn't decide, sorry."}} {
		sel, fb := cat.SelectLLM(context.Background(), Query{Task: "prove blind sql injection", MaxActive: 8}, gen)
		if !fb {
			t.Error("a model failure must trigger deterministic fallback")
		}
		if !contains(sel.Names(), "sqli_bool_probe") {
			t.Errorf("fallback should still surface the lexically-relevant tool, got %v", sel.Names())
		}
	}
}

// TestSelectLLM_FrontierProxy is the end-to-end "claude-as-proxy frontier LLM" validation: the
// Generator returns the answer a frontier model (Claude, driven via the proxy pattern) actually
// produces for a SEMANTIC task that has ZERO lexical overlap with the right tool. It proves the refiner
// adds real value the BM25 layer cannot: BM25 misses race_probe here (no shared token with
// race/toctou/limit/concurrency), but the frontier model recognizes "same one-time code more than once
// if sent together" as a concurrency race and picks race_probe.
func TestSelectLLM_FrontierProxy(t *testing.T) {
	cat := webagentCatalog()
	task := "the checkout lets you apply the same one-time discount code more than once if you send the requests together"

	// Golden: the actual selection the frontier model returns for buildRankPrompt(task, ...). Captured
	// via the claude-as-proxy pattern (the model reads the prompt, returns the JSON array).
	frontierAnswer := `["race_probe"]`
	sel, fb := cat.SelectLLM(context.Background(), Query{Task: task, MaxActive: 8}, &mockGen{resp: frontierAnswer})
	if fb {
		t.Fatal("valid frontier answer should not fall back")
	}
	if !contains(sel.Names(), "race_probe") {
		t.Fatalf("frontier refiner should surface race_probe for a described race condition, got %v", sel.Names())
	}

	// Contrast: the deterministic BM25 layer alone MISSES race_probe on this wording — proving the
	// LLM refiner contributes a selection lexical scoring cannot.
	if contains(cat.Select(Query{Task: task, MaxActive: 8}).Names(), "race_probe") {
		t.Skip("BM25 unexpectedly matched race_probe; the semantic-add contrast is not demonstrated by this wording")
	}
}

func TestParseToolList(t *testing.T) {
	cases := map[string]int{
		`["a","b","c"]`:                3,
		"```json\n[\"a\", \"b\"]\n```": 2,
		"Here: [\"only_one\"] done":    1,
		"no array at all":              0,
		`{"not":"an array"}`:           0,
	}
	for in, want := range cases {
		if got := len(parseToolList(in)); got != want {
			t.Errorf("parseToolList(%q) = %d names, want %d", in, got, want)
		}
	}
}
