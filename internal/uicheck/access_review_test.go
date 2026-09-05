package uicheck

import (
	"strings"
	"testing"
)

// The access review is filed as SOC 2 CC6.2/CC6.3 evidence, and its two most dangerous
// misreadings are both WORDING rather than a missing field — which is why the shared
// field table in uicheck_test.go cannot cover them.
//
//  1. "Mark for removal" must never read as "removed". Recording the verdict is an
//     attestation; the removal is a change, and every change in this product goes through
//     the approval desk (§18.2 inv. 3). A reviewer who closes the campaign believing the
//     accounts are gone is the worst outcome this screen can produce, and nothing in the
//     data model would tell them otherwise.
//  2. The reviewer's NAME is what turns the decision into evidence. The server refuses an
//     unattributed decision ("name the person reviewing this access"), so a form without
//     that input hands the user a 400 they cannot act on.
//
// FAILS rather than skips when a file moves (§14.2 rule 6) — frontendFile fatals.
func TestAccessReviewDoesNotClaimItRemovedAnything(t *testing.T) {
	src := frontendFile(t, "components", "access-review", "decide-access.tsx")

	if !strings.Contains(src, "does not remove the access") {
		t.Error("decide-access.tsx never says that recording a removal does not remove the access.\n\n" +
			"Without it the reviewer reads the button as the act. The verdict is recorded and signed; " +
			"the change itself is proposed separately and still has to be approved.")
	}
	if strings.Contains(src, ">Revoke<") || strings.Contains(src, "Revoke access") {
		t.Error(`decide-access.tsx labels the button "Revoke", which asserts the act rather than the ` +
			`verdict. Use "Mark for removal" — the button records a decision, it does not cut access.`)
	}
	if !strings.Contains(src, `name="by"`) {
		t.Error("decide-access.tsx has no reviewer-name input.\n\n" +
			"The server REFUSES a decision with no named reviewer, because an unattributed decision " +
			"is a log line rather than audit evidence — so without this field every submission 400s.")
	}
}

// The empty campaign is the case an auditor must never misread: nobody flagged is not a
// completed review. The server writes that sentence; the page renders it verbatim and must
// not compute a completion claim of its own.
func TestAccessReviewPageDefersToTheServersCompletionClaim(t *testing.T) {
	src := frontendFile(t, "app", "(app)", "access-review", "page.tsx")

	if !strings.Contains(src, "p.complete") {
		t.Error("the access-review page never reads progress.complete — a completion claim computed " +
			"in the page (e.g. pending === 0) would call an EMPTY campaign complete, which is exactly " +
			"the audit artifact recertify.Summarize refuses to produce.")
	}
	if strings.Contains(src, "p.pending === 0") || strings.Contains(src, "pending === 0") {
		t.Error("the access-review page derives completion from a pending count of zero. An empty " +
			"campaign has zero pending and is NOT a completed access review; use the server's " +
			"progress.complete, which is false when total is 0.")
	}
}
