package agentmemory

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func joined(m Memory) string {
	var b strings.Builder
	for _, l := range m.PromptLines() {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// Every kind of fact the customer already gave us reaches the memory, each naming where it lives.
func TestBuild_JoinsWhatTheCustomerAlreadySaid(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	m := Build(Inputs{
		Now: now,
		Tenant: platform.Tenant{
			AgentNotes: []platform.AgentNote{{ID: "n1", Text: "We never\nauto-merge on Fridays", By: "cto@acme.com", At: now}},
			OutOfScope: map[string]platform.ScopeExclusion{"a-legacy": {By: "cto@acme.com", Reason: "decommissioning in Q1"}},
		},
		Assets: []platform.Asset{
			{ID: "a-pay", Target: "https://pay.acme.com", Owner: "priya@acme.com", Team: "payments"},
			{ID: "a-legacy", Target: "https://old.acme.com"},
		},
		Ignores: []platform.IgnoreRule{
			{IssueKey: "nuclei::x|https://pay.acme.com", Reason: "accepted_risk", Note: "behind VPN", At: now, ExpiresAt: now.AddDate(0, 1, 0)},
			{IssueKey: "lapsed-key", Reason: "accepted_risk", At: now.AddDate(0, -3, 0), ExpiresAt: now.AddDate(0, 0, -1)},
		},
		Actions: []platform.Action{
			{ID: "act1", Title: "Pin lodash", Status: platform.ActRejected, Approver: "priya@acme.com", Feedback: "we use renovate for this", Payload: map[string]any{"remediation_type": "dependency_upgrade"}},
			{ID: "act2", Title: "Untouched", Status: platform.ActPendingApproval},
		},
		Feedback: []platform.Feedback{{IssueKey: "semgrep::sqli|repo/a.go:10", Evidence: platform.EvidenceInsufficient, Note: "show the request", At: now}},
	})
	s := joined(m)
	for _, want := range []string{
		"[note] We never auto-merge on Fridays", // newline flattened: a note cannot break the prompt's structure
		"[owner] https://pay.acme.com is owned by priya@acme.com (payments)",
		"[out_of_scope] https://old.acme.com is out of scope — decommissioning in Q1",
		"[decision] issue nuclei::x|https://pay.acme.com",
		"[declined_fix] fix “Pin lodash” (dependency_upgrade) was rejected: we use renovate for this",
		"[explain] issue semgrep::sqli|repo/a.go:10",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "lapsed-key") {
		t.Error("a lapsed risk decision is back on the list; remembering it as in force would hide it")
	}
	if strings.Contains(s, "Untouched") {
		t.Error("a pending fix is not a declined one")
	}
	for _, l := range m.Lines {
		if l.Source == "" {
			t.Errorf("every line must say where it lives so it can be corrected there: %+v", l)
		}
	}
}

// The caps keep memory from crowding the findings out — and what they drop is SAID.
func TestBuild_CapsAreStated(t *testing.T) {
	var notes []platform.AgentNote
	for i := 0; i < 25; i++ {
		notes = append(notes, platform.AgentNote{ID: string(rune('a' + i)), Text: "note"})
	}
	m := Build(Inputs{Tenant: platform.Tenant{AgentNotes: notes}})
	if got := len(m.Lines); got != caps[KindNote] {
		t.Fatalf("notes not capped: %d", got)
	}
	if m.Omitted[KindNote] != 5 || !strings.Contains(joined(m), "more not shown: 5 note") {
		t.Errorf("the cap must be stated: %+v", m.Omitted)
	}
}
