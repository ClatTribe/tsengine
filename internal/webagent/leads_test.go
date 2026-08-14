package webagent

import (
	"strings"
	"testing"
)

func promptWithLeads(leads []EstateLead) string {
	cc := &Context{
		Target: "https://shop.example.com",
		Routes: []string{"https://shop.example.com/login", "https://shop.example.com/blog"},
		Leads:  leads,
		req:    NewRequester([]string{"shop.example.com"}, 50, 0),
	}
	return buildPrompt(cc, nil)
}

// The pentester otherwise sees a flat list of URLs and cannot tell the login form fronting a PII
// warehouse from the one fronting a blog. The lead is what lets it spend its budget by stakes.
func TestLeads_TellThePentesterWhatARouteReaches(t *testing.T) {
	p := promptWithLeads([]EstateLead{{
		Route:   "https://shop.example.com/login",
		Reaches: "a table declared to hold PII",
		Why:     "a leaked key committed near this handler assumes the role that can read it",
	}})
	if !strings.Contains(p, "/login reaches a table declared to hold PII") {
		t.Errorf("the lead did not reach the prompt:\n%s", p)
	}
	if !strings.Contains(p, "leaked key committed near this handler") {
		t.Error("the chain explanation was dropped")
	}
}

// THE INJECTION BOUNDARY, RESTATED FOR LEADS.
//
// A lead is estate context, not evidence. The prompt must say so in as many words, because a model that
// treats "this route reaches PII" as a reason to REPORT a vuln has skipped the proof — and record_finding
// would still reject it (requiredIndicator), but the prompt should not invite the attempt.
func TestLeads_AreFramedAsContextNotProof(t *testing.T) {
	// Assert against the LEADS block specifically, not the whole prompt. The L1-seeds block also
	// contains "not proof" (an L1 alert is a lead, not proof), so a whole-prompt Contains would pass
	// even if the leads block dropped its framing entirely — which is exactly the false pass an earlier
	// version of this test gave. Slice from the leads header to the next section so the mutation that
	// guts the leads framing actually fails here.
	p := promptWithLeads([]EstateLead{{Route: "https://shop.example.com/login", Reaches: "an admin identity"}})
	block := leadsBlock(t, p)
	low := strings.ToLower(block)
	if !strings.Contains(low, "not proof") {
		t.Errorf("the LEADS block never says a lead is not proof of a vuln:\n%s", block)
	}
	if !strings.Contains(low, "still have to") && !strings.Contains(low, "ground the vuln") {
		t.Errorf("the LEADS block does not tell the agent it must still ground the vuln:\n%s", block)
	}
}

// leadsBlock isolates the "WHAT THESE ROUTES REACH" section so an assertion about the leads framing
// cannot be satisfied by identical words living in a different block.
func leadsBlock(t *testing.T, prompt string) string {
	t.Helper()
	const header = "WHAT THESE ROUTES REACH"
	i := strings.Index(prompt, header)
	if i < 0 {
		t.Fatalf("no leads block in prompt:\n%s", prompt)
	}
	rest := prompt[i:]
	// The block ends at the next all-caps section header or the tool list.
	for _, next := range []string{"DEFENSES OBSERVED", "REQUESTS USED", "TOOLS:"} {
		if j := strings.Index(rest, next); j > 0 {
			rest = rest[:j]
		}
	}
	return rest
}

// STRUCTURAL PROOF THAT A LEAD CANNOT FORGE A FINDING.
//
// The framing above is guidance; this is the guarantee. Grounding lives in requiredIndicator, which
// record_finding consults and which has no connection to Context.Leads whatsoever. So no lead — however
// worded — can satisfy the indicator a class demands. If this ever changes, leads would become an
// injection vector, so the test pins the independence.
func TestLeads_CannotSatisfyAGroundingIndicator(t *testing.T) {
	for class, indicators := range requiredIndicator {
		for _, ind := range indicators {
			// A lead's fields are free text an upstream graph produced. None of them is an indicator
			// name, and even if one were, record_finding reads indicators off the cited TURN, not off
			// the leads. Assert the indicator vocabulary shares nothing with a lead's structure.
			if ind == "reaches" || ind == "why" || ind == "route" {
				t.Errorf("class %q requires indicator %q, which collides with an EstateLead field — "+
					"a lead could then be mistaken for proof", class, ind)
			}
		}
	}
}

// No leads → the block is absent entirely, so a deployment without a graph sees byte-identical behaviour
// to before this existed. An empty section header with nothing under it would be its own small lie.
func TestLeads_AbsentWhenNoneSupplied(t *testing.T) {
	p := promptWithLeads(nil)
	if strings.Contains(p, "WHAT THESE ROUTES REACH") {
		t.Errorf("the leads header rendered with no leads:\n%s", p)
	}
}

// A lead with no Why still renders usefully — the Reaches alone is the reason to prioritise.
func TestLeads_RenderWithoutAChainExplanation(t *testing.T) {
	p := promptWithLeads([]EstateLead{{Route: "https://shop.example.com/login", Reaches: "an admin identity"}})
	if !strings.Contains(p, "/login reaches an admin identity") {
		t.Errorf("a lead without Why did not render:\n%s", p)
	}
}
