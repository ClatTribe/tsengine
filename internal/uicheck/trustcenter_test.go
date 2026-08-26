package uicheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// trustcenter_test.go guards the READER half of the Trust Center.
//
// CLAUDE.md §11 names this failure by shape: a signal gets wired where the author is working and
// the human surface is a separate file nobody opens, so ASSUME the reader half is missing until
// checked. The Trust Center has four such signals, and each one is a refusal that only exists if
// somebody sees it:
//
//   - The server CLAMPS a document that names open findings out of "public" and returns a
//     correction saying so. Rendered nowhere, the owner saves "public", the API stores "gated",
//     and the owner believes their pentest report is published when it is not — or, far worse,
//     believes some later setting took effect when it silently did not.
//   - The server DROPS a document nothing can produce from the public page, on purpose, because a
//     locked row asserts the document exists. That omission is invisible by design, so the owner
//     is told separately or it reads as a bug.
//   - The buyer page distinguishes "waiting on a human" from "waiting on your own signature". The
//     buyer can act on exactly one of those.
//   - A generated document says it was generated from live posture rather than uploaded. That is
//     the whole claim the product is making on that page.
//
// Every check here reads the real source file and FAILS rather than skips when it cannot find it
// (§14.2 rule 6): a guard that goes quiet when its subject moves is green at the moment it is
// least able to see.

func frontendFile(t *testing.T, parts ...string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "frontend"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(append([]string{root}, parts...)...)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — if it moved, move this guard with it", path, err)
	}
	return string(src)
}

func TestTrustCenterPanelShowsCorrectionsAndOmissions(t *testing.T) {
	src := frontendFile(t, "components", "settings", "trust-center-control.tsx")

	if !strings.Contains(src, "corrections") {
		t.Error("the Trust Center panel never reads the save's corrections. The server rewrites what " +
			"the owner submitted — clamping a findings-bearing document out of public, dropping a " +
			"wildcard auto-approve rule — and a config silently altered is one the owner believes says " +
			"something it does not.")
	}
	if !strings.Contains(src, "unavailable") {
		t.Error("the panel never reads `unavailable`. A document nothing can produce is left off the " +
			"public page deliberately, so without this the owner sees a row they configured simply not " +
			"appear, with nothing saying why.")
	}
	// The owner must not be offered a choice the server will refuse. The server still clamps —
	// this is the courtesy half, and its absence is what would invite the attempt.
	if !strings.Contains(src, "NEVER_PUBLIC") {
		t.Error("the panel offers the same visibility choices for every document kind. A compliance " +
			"report, a VAPT report and an evidence pack name open findings and can never be public; " +
			"rendering the option invites an owner to try to publish an attacker's roadmap.")
	}
	if !strings.Contains(src, "Revoke this link") {
		t.Error("the panel has no way to revoke the share link. The token is revocable now — that was " +
			"the point of versioning it — and a capability with no control is one nobody has.")
	}
}

func TestTrustDeskDistinguishesApprovedFromGranted(t *testing.T) {
	src := frontendFile(t, "components", "settings", "trust-requests-desk.tsx")

	if !strings.Contains(src, "granted") {
		t.Error("the access desk never reads the server's `granted`. A request can be approved and " +
			"ungranted — expired, revoked, agreement outstanding — and a desk that showed \"approved\" " +
			"for all of those misreports who currently has access.")
	}
	if !strings.Contains(src, "auto_approved") {
		t.Error("the desk does not distinguish a rule's approval from a person's. Rendered alike, a " +
			"decision nobody reviewed reads as one somebody did.")
	}
	if !strings.Contains(src, "Shown once") {
		t.Error("the desk does not warn that the access link cannot be shown again. Only its digest is " +
			"stored, so an owner who navigates away has to approve a second time and will not know why.")
	}
}

func TestPublicTrustPageSeparatesTheTwoWaitingStates(t *testing.T) {
	src := frontendFile(t, "components", "trust", "document-tier.tsx")

	if !strings.Contains(src, "nda_pending") {
		t.Error("the buyer page does not read nda_pending, so it cannot tell someone whether they are " +
			"waiting on a human or on their own signature — and only one of those is something they " +
			"can act on.")
	}
	if !strings.Contains(src, "generated") {
		t.Error("the buyer page does not distinguish a document generated from live posture from a " +
			"link to a hosted file. That distinction is the product's actual claim on this page: " +
			"everyone else serves a PDF someone uploaded.")
	}
	// The gate decisions are the server's. A page that recomputed them would eventually disagree
	// with the endpoint — visibly as a row that looks open and 403s, invisibly as one that looks
	// locked while its document is served.
	if !strings.Contains(src, "e.readable") && !strings.Contains(src, ".readable") {
		t.Error("the buyer page does not render the server's `readable`. Deriving it client-side lets " +
			"the listing and the fetch disagree about what is gated.")
	}
}
