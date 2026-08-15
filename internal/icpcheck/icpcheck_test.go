// Package icpcheck holds no runtime code — like internal/legalcheck it exists solely to gate
// PUBLISHED marketing copy in CI, where `go test ./...` already runs and the frontend (lint +
// typecheck + build, no test runner) would otherwise never check a claim.
//
// It guards two properties. The first is housekeeping; the second is a correctness defect.
//
// # 1. The audience label says who we actually sell to
//
// The funnel had drifted to "for Series A teams" on the homepage title, nav, footer and startups
// page while the product is sold to Series A AND B. A visitor at Series B reading "for Series A
// teams" rules themselves out in the one line written to help them rule themselves in.
//
// # 2. Marketing must not sell away the human the architecture REQUIRES
//
// This is the one that matters. The product structurally cannot run without a named human:
// hitl.Desk refuses to apply a gated action with no approver, and an irreversible (tier-3) action
// refuses without a named signature (§18.2 inv. 3, platform.Action.NeedsHumanSignature). Copy
// promising "no security hire needed" therefore sells a product we deliberately did not build —
// and the buyer discovers it at the moment the first gated action lands in their inbox and nobody
// on the team feels qualified to approve it.
//
// The fix is not to weaken the gate. Requiring a human is the differentiator against "fully
// autonomous" competitors, and it is what makes the signed ledger worth anything. So the copy has
// to say it: the agent does the work, a named person on your team keeps the call.
//
// The phrases below are matched narrowly and deliberately. "Security shouldn't require a security
// hire" — the mission statement on /about — is NOT one of them: it says the WORK should not need a
// dedicated hire, which is our thesis, not that no human is ever in the loop.
package icpcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// frontendDir resolves the published frontend, skipping when it is not checked out beside us.
func frontendDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "frontend"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("frontend not present (%v) — skipping positioning guard", err)
	}
	return dir
}

// copyFiles walks the marketing pages and their components — the surfaces a prospect reads. The
// signed-in app is excluded: it talks to customers who already bought, in different language.
func copyFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, sub := range []string{
		filepath.Join("app", "(marketing)"),
		filepath.Join("components", "marketing"),
		filepath.Join("lib", "solutions.ts"),
	} {
		p := filepath.Join(root, sub)
		_ = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err != nil || d == nil || d.IsDir() {
				return nil //nolint:nilerr // a missing optional surface is not a test failure
			}
			if ext := filepath.Ext(path); ext != ".tsx" && ext != ".ts" {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil //nolint:nilerr // unreadable file reported by the walk, not fatal here
			}
			rel, _ := filepath.Rel(root, path)
			out[rel] = string(b)
			return nil
		})
	}
	if len(out) == 0 {
		t.Skip("no marketing copy found — skipping positioning guard")
	}
	return out
}

// ── 1. THE AUDIENCE LABEL ────────────────────────────────────────────────────────────────────────

// audienceRe matches "Series A" used as an AUDIENCE label — directly qualifying a team, startup or
// company. Narrow on purpose: prose that merely mentions a funding round ("after their Series A")
// is not a positioning claim and must not trip this.
var audienceRe = regexp.MustCompile(`(?i)Series A (teams?|startups?|compan(y|ies))`)

// TestAudienceLabelIncludesSeriesB fails when a page addresses Series A alone.
//
// The product is sold to Series A and B. A Series B visitor who reads "for Series A teams" in the
// qualifier line has been told, by the sentence written to help them self-identify, that this is
// not for them.
func TestAudienceLabelIncludesSeriesB(t *testing.T) {
	for rel, src := range copyFiles(t, frontendDir(t)) {
		for _, line := range strings.Split(src, "\n") {
			if !audienceRe.MatchString(line) {
				continue
			}
			// "Series A and B teams" is the correct form; so is any line that names B alongside.
			if strings.Contains(line, "A and B") || strings.Contains(line, "and Series B") {
				continue
			}
			t.Errorf("%s addresses Series A alone:\n  %s\n"+
				"The product is sold to Series A AND B — a Series B visitor reading this rules "+
				"themselves out. Use \"Series A and B teams\".", rel, strings.TrimSpace(line))
		}
	}
}

// ── 2. THE HUMAN THE ARCHITECTURE REQUIRES ───────────────────────────────────────────────────────

// noHumanClaims are phrases asserting the product needs nobody. Each is a promise the gate cannot
// keep: hitl.Desk refuses an approved-by-nobody apply, and tier-3 refuses without a named
// signature. Matched as fixed phrases so ordinary copy about hiring is unaffected.
var noHumanClaims = []string{
	"no security hire needed",
	"without a security hire",
	"no security team needed",
	"without a security team",
	"replaces your security team",
	"replace your security team",
	"fully autonomous",
	"no human needed",
	"without human review",
	"without any human",
}

// TestCopyDoesNotSellAwayTheApprover is the substantive guard: marketing may not promise an
// autonomy the product deliberately refuses to have.
//
// This is not a tone preference. A buyer sold "no security hire needed" has been told the agent
// will act on its own; the first gated action proves otherwise, and the gap between the two is
// discovered by the customer rather than by us.
func TestCopyDoesNotSellAwayTheApprover(t *testing.T) {
	for rel, src := range copyFiles(t, frontendDir(t)) {
		low := strings.ToLower(src)
		for _, claim := range noHumanClaims {
			if !strings.Contains(low, claim) {
				continue
			}
			t.Errorf("%s claims %q.\n"+
				"The product cannot deliver that: hitl.Desk refuses to apply a gated action with no "+
				"approver, and an irreversible action refuses without a named signature (§18.2 inv. 3). "+
				"Say what is true — the agent does the work, a named person on the team approves "+
				"anything that touches their systems.", rel, claim)
		}
	}
}

// TestHomepageStatesTheApprovalGate is the same property from the other side. Requiring a human is
// the differentiator against "fully autonomous" tools and the reason the signed ledger is worth
// anything; a homepage that omits it undersells the product AND leaves the buyer surprised by the
// approval queue.
func TestHomepageStatesTheApprovalGate(t *testing.T) {
	root := frontendDir(t)
	b, err := os.ReadFile(filepath.Join(root, "app", "(marketing)", "page.tsx"))
	if err != nil {
		t.Skipf("homepage not present (%v)", err)
	}
	low := strings.ToLower(string(b))
	// Any phrasing will do — the property is that approval is STATED, not that it is worded a
	// particular way, so ordinary copy edits do not break this test.
	for _, ok := range []string{"approve", "approval", "sign off", "signs off"} {
		if strings.Contains(low, ok) {
			return
		}
	}
	t.Error("the homepage never mentions that a human approves changes.\n" +
		"That gate is the product's central claim against fully-autonomous competitors, and a buyer " +
		"who does not expect it meets it for the first time in their inbox.")
}
