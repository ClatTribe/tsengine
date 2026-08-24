package grc

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// vapt_rung_test.go is the customer-facing half of ADR 0029 D2d.
//
// The rung vocabulary is unit-tested in pkg/types. What matters HERE is that the report actually
// prints it: this document is the one a customer forwards to an auditor, and it was rendering the
// bare word "verified" for both an exploit we ran and a cloud path a policy simulator merely
// authorized.

func TestVAPTMarkdown_TellsAnExploitApartFromAnAuthorization(t *testing.T) {
	r := &VAPTReport{
		Findings: []VAPTFinding{
			{
				ID: "f1", Title: "SQL injection in search", Severity: "high", Tool: "web-investigate",
				Rung: string(types.RungExploited), Verification: "verified",
			},
			{
				ID: "f2", Title: "Role can escalate to admin", Severity: "high", Tool: "cloudagent",
				Rung: string(types.RungProviderConfirmed), Verification: "verified",
			},
		},
	}

	md := RenderVAPTMarkdown(r)

	if !strings.Contains(md, "we ran the attack and it worked") {
		t.Error("the report never says an exploited finding was exploited")
	}
	if !strings.Contains(md, "authorization, not exploitation") {
		t.Error("the report does not carry the authorization-is-not-exploitation caveat for a " +
			"provider-confirmed cloud path. Without it an auditor reads both findings as proven attacks.")
	}
	// The regression that matters: the two must not render the same phrase.
	if strings.Count(md, "we ran the attack and it worked") != 1 {
		t.Error("the exploited phrasing appears somewhere other than the exploited finding")
	}
}

func TestVAPTMarkdown_StillSaysSomethingWhenNoRungWasComputed(t *testing.T) {
	// Back-compat and the honest floor. A report built before this field existed, or by a caller that
	// does not set it, must not print an empty evidence line.
	r := &VAPTReport{Findings: []VAPTFinding{
		{ID: "f3", Title: "Outdated dependency", Severity: "medium", Tool: "trivy", Verification: "corroborated"},
	}}

	md := RenderVAPTMarkdown(r)

	if !strings.Contains(md, "Evidence strength:") {
		t.Fatal("no evidence-strength line at all")
	}
	if strings.Contains(md, "Evidence strength:** \n") || strings.Contains(md, "Evidence strength:**\n") {
		t.Error("the evidence-strength line is empty — a blank claim reads as no claim, and the reader " +
			"supplies their own")
	}
	if !strings.Contains(md, "corroborated") {
		t.Errorf("the fallback should still print the verification state; got:\n%s", md)
	}
}

func TestVAPTMarkdown_AContradictionIsShownNotSmoothedOver(t *testing.T) {
	// A captured proof-of-concept with a rung that is not "exploited" should not happen. If it ever
	// does, the report must show both rather than quietly picking one — a mismatch here is a bug
	// somewhere upstream and hiding it would make that bug invisible.
	r := &VAPTReport{Findings: []VAPTFinding{{
		ID: "f4", Title: "Odd one", Severity: "high", Tool: "nuclei",
		Rung: string(types.RungCorroborated), PoC: "[Exploitation PoC] GET /x",
	}}}

	md := RenderVAPTMarkdown(r)

	if !strings.Contains(md, "exploitation-proven") {
		t.Error("a captured PoC disappeared from the evidence line because the rung disagreed with it")
	}
	if !strings.Contains(md, "corroborated") {
		t.Error("the rung disappeared too — the reader can no longer see that the two disagree")
	}
}
