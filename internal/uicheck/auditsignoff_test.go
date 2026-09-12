package uicheck

import (
	"strings"
	"testing"
)

// The sign-off desk produces a certificate a government buyer relies on and cannot look behind. These
// hold the screen to the refusals internal/auditreview makes server-side — a page that quietly
// dropped any of them would still compile and still look finished.
//
// FAILS rather than skips when a file moves (§14.2 rule 6): frontendFile fatals.

// THE LOAD SPLIT is why this surface exists rather than a findings list. A finding the engine PROVED
// is a glance; one resting on a pattern match is the reviewer's name on the scanner's word. Rendered
// alike, the reviewer spreads an hour evenly over twelve findings instead of spending it on the four
// that need it.
func TestAuditSignoffShowsWhereJudgementIsActuallyNeeded(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "audit-signoff", "page.tsx"))

	for _, f := range []string{"load.proven", "load.unproven", "load.detail"} {
		if !strings.Contains(page, f) {
			t.Errorf("the sign-off page never renders %s — without the split the reviewer cannot tell "+
				"which findings need their judgement and which are checking the engine's work", f)
		}
	}
	if !strings.Contains(page, "i.proven") {
		t.Error("per finding, the page never shows whether a predicate proved it. A pattern match and " +
			"an exploited finding would render identically, which is the one distinction the reviewer " +
			"is being paid to make.")
	}
}

// The empty review is the dangerous case: zero findings is as likely a scan that never ran as a clean
// application, and this page is one step from a certificate.
func TestAuditSignoffDefersToTheServersCompletionClaim(t *testing.T) {
	page := stripComments(frontendFile(t, "app", "(app)", "audit-signoff", "page.tsx"))

	if !strings.Contains(page, "p.detail") {
		t.Error("the page never renders the server's own sentence about what the numbers mean — it is " +
			"what keeps an empty review from reading as a clean audit")
	}
	if !strings.Contains(page, "p.complete") {
		t.Error("the page does not read progress.complete")
	}
	if strings.Contains(page, "p.pending === 0") || strings.Contains(page, "pending.length === 0") {
		t.Error("the page derives completion from a pending count of zero. An EMPTY review has zero " +
			"pending and is not a completed audit — use the server's progress.complete, which is false " +
			"when total is 0.")
	}
}

// Blockers must be visible while the reviewer works, not discovered at the button — and all of them
// at once, since fixing one and re-submitting to find the next is the loop this removes.
func TestAuditSignoffShowsEveryBlockerBeforeTheButtonIsPressed(t *testing.T) {
	cert := frontendFile(t, "components", "audit-signoff", "issue-certificate.tsx")

	if !strings.Contains(cert, "blockers.map") {
		t.Error("the certificate control does not list the blockers, so a reviewer learns why it is " +
			"refused only by pressing the button")
	}
	if !strings.Contains(cert, "not a guarantee") {
		t.Error("the control does not tell the reviewer what the certificate actually says about its " +
			"own limits before they issue it")
	}
	if !strings.Contains(cert, "Not covered by this assessment") {
		t.Error("no way to record scope the auditor knows was excluded. A certificate that lists only " +
			"what was checked reads as though everything was.")
	}
}

// THE COMMERCIAL TERM ON SCREEN. Every tender this SKU serves pays 100% on acceptance and never in
// advance, and the server computes the amount due from the order's status. A panel that derived a
// figure of its own — price × "certificate issued" — would invoice work the buyer has not accepted,
// on the one page an operator raises invoices from.
func TestAuditSignoffOrderPanelStatesOnlyTheServersAmountDue(t *testing.T) {
	panel := stripComments(frontendFile(t, "components", "audit-signoff", "order-panel.tsx"))

	if !strings.Contains(panel, "amount_due_inr") {
		t.Error("the order panel never renders the server's amount_due_inr — the one figure that " +
			"encodes 'nothing is owed before acceptance'")
	}
	if !strings.Contains(panel, "no advance") {
		t.Error("the panel does not state the no-advance term where the order is opened")
	}
	if strings.Contains(panel, "price_inr *") || strings.Contains(panel, "* order.price_inr") {
		t.Error("the panel computes money from the price itself; the amount due is the server's to say")
	}
	page := stripComments(frontendFile(t, "app", "(app)", "audit-signoff", "page.tsx"))
	if !strings.Contains(page, "OrderPanel") {
		t.Error("the desk does not show the order, so the reviewer cannot see what this application is being charged")
	}
}

// An exclusion is not a deletion, and a bulk control would turn the one decision that cannot be
// automated into a single click.
func TestAuditSignoffRefusesToMakeExclusionLookLikeTidyingUp(t *testing.T) {
	dec := frontendFile(t, "components", "audit-signoff", "decide-finding.tsx")

	if !strings.Contains(dec, "does not delete the finding") {
		t.Error("the exclude control does not say the finding stays in the record. Presented as a " +
			"removal, it becomes the button a reviewer uses to tidy a report.")
	}
	if !strings.Contains(dec, "required") {
		t.Error("the reason field is not required in the form, so a reviewer meets the server's refusal " +
			"as an error instead of a field")
	}
	page := stripComments(frontendFile(t, "app", "(app)", "audit-signoff", "page.tsx"))
	for _, banned := range []string{"Include all", "Approve all", "Accept all", "includeAll"} {
		if strings.Contains(page, banned) || strings.Contains(dec, banned) {
			t.Errorf("a bulk control (%q) turns the one decision that cannot be automated into a click", banned)
		}
	}
}
