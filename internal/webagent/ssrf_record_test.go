package webagent

import (
	"context"
	"strings"
	"testing"
)

// TestRecordFinding_SSRF_OOBGrounded: a (blind) SSRF proven by an out-of-band callback must be
// RECORDABLE + VERIFIABLE. Before this, record_finding had no `ssrf` class, so the agent could make the
// target fetch an attacker URL and see the callback in oob_check — but could NOT put SSRF in the report
// (observed live: XBEN-024/033 captured the flag with 0 findings). The grounding is FP-free by
// construction: the `oob_interaction` indicator is set ONLY when the collector recorded a real inbound
// callback (the target literally reached the attacker's URL — §10), and only tOOBCheck can set it.
func TestRecordFinding_SSRF_OOBGrounded(t *testing.T) {
	if !contains(requiredIndicator["ssrf"], "oob_interaction") {
		t.Fatalf("ssrf must be grounded by the oob_interaction indicator, got %v", requiredIndicator["ssrf"])
	}

	// A collector that already recorded a callback for token z1abcd (as if the target fetched our URL).
	col := NewCollector("")
	col.hits = append(col.hits, OOBHit{Token: "z1abcd", Method: "GET", Path: "/z1abcd"})
	cc := &Context{ctx: context.Background(), oob: col}

	// oob_check must emit a CITABLE turn carrying oob_interaction when a hit exists.
	chk := tOOBCheck(cc, map[string]any{"token": "z1abcd"})
	if !strings.Contains(chk, "oob_interaction") && !strings.Contains(chk, "t-0") {
		t.Fatalf("oob_check with a hit should surface a citable turn: %s", chk)
	}
	var oobTurn string
	for _, tn := range cc.History {
		if hasIndicator(tn, "oob_interaction") {
			oobTurn = tn.ID
		}
	}
	if oobTurn == "" {
		t.Fatalf("oob_check did not append a turn carrying the oob_interaction indicator; history=%+v", cc.History)
	}

	out := tRecord(cc, map[string]any{
		"route": "/fetch?url=", "class": "ssrf", "evidence": []any{oobTurn},
		"severity": "high", "rationale": "the target fetched our OOB URL — blind SSRF",
	})
	if strings.Contains(out, "REJECTED") {
		t.Fatalf("ssrf finding rejected despite an oob_interaction turn: %s", out)
	}
	if len(cc.Findings) != 1 || cc.Findings[0].Class != "ssrf" {
		t.Fatalf("ssrf finding not recorded: %+v", cc.Findings)
	}

	// confirm_exploit for an OOB-grounded finding re-checks the DURABLE callback, not an HTTP re-fire
	// (the signal is out-of-band, not in any response body). cc.req is nil here — the OOB path must not
	// touch it.
	cout := tConfirm(cc, map[string]any{"finding_id": cc.Findings[0].ID})
	if !strings.Contains(cout, "VERIFIED") {
		t.Fatalf("ssrf confirm should verify from the recorded OOB callback: %s", cout)
	}

	// NEGATIVE: claiming ssrf with a turn that does NOT carry oob_interaction must be REJECTED (no FP).
	cc2 := &Context{ctx: context.Background(), oob: NewCollector("")}
	cc2.History = []Turn{{ID: "t-001", Indicators: []string{"reflected_input"}}}
	out2 := tRecord(cc2, map[string]any{"class": "ssrf", "evidence": []any{"t-001"}, "severity": "high"})
	if !strings.Contains(out2, "REJECTED") {
		t.Errorf("ssrf without an oob_interaction turn must be rejected: %s", out2)
	}
}
