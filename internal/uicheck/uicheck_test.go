// Package uicheck holds no runtime code. It gates a contract the compiler cannot see: that a
// screen making a COVERAGE claim also renders the fields which qualify that claim.
//
// Why a Go test for TypeScript: the frontend has no test runner (its CI job is lint + typecheck
// + build), but `go test ./...` runs on every PR. Same reasoning as internal/legalcheck.
//
// WHY THIS EXISTS. CLAUDE.md §18 records three defects with one shape — the backend knew
// something was wrong and the screen did not say so — and notes that a component test would not
// have caught them, because it tests the component against the props you passed it. This is the
// variant where the data is right there in the response and the component ignores it:
//
//   - coverage.AssetCoverage.ToolsFailed was computed, persisted on the Engagement, and covered
//     by a Go test asserting "a failed tool must be named, not folded into 'ran clean'". The
//     coverage page never read it, and labelled every non-hit tool "ran, found nothing" — so a
//     tool that never ran rendered identically to one that ran clean, on the page whose own copy
//     promises "you never have to take coverage on trust".
//
//   - coverage.AssetCoverage.ExecutionConfirmed has a doc comment stating the field exists "so
//     the UI states what is known rather than the reassuring version", and naming the exact case:
//     a TOOLSET-limited image where the tool is a stub, which "produces zero findings and, before
//     this, was reported to the customer as 'All tools ran and found nothing'". The UI never read
//     it either. The field was created FOR a consumer that never consumed it.
//
// Both were found by asking what the screen does with each field the API already sends. Neither
// was a bug in Go, so no Go test could fail; both were invisible in TypeScript, because rendering
// nothing compiles.
package uicheck

import (
	"os"
	"regexp"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tenanteval"
)

// Each entry: a page, a field of the API contract that QUALIFIES what that page asserts, and the
// claim the page would otherwise make unqualified. A field listed here must appear in the page
// source — crude, deliberately: the failure mode is the field being referenced NOWHERE, and that
// is exactly what a substring check detects.
//
// This is not a general rule that every field must be rendered. It is a list of the ones whose
// absence turns a page into an overstatement, which is the §10 line.
var required = []struct {
	page, field, wouldOtherwiseClaim string
}{
	{
		page:  "frontend/app/(app)/coverage/page.tsx",
		field: "tools_failed",
		wouldOtherwiseClaim: "that a tool which never ran 'ran, found nothing' — a clean result " +
			"from a tool that has no opinion about the target",
	},
	{
		page:  "frontend/app/(app)/coverage/page.tsx",
		field: "execution_confirmed",
		wouldOtherwiseClaim: "that the listed tools RAN, when the scan never reported what it " +
			"dispatched and the list is only what this asset type is configured to run",
	},
	{
		page:  "frontend/app/(app)/coverage/page.tsx",
		field: "declared_gaps",
		wouldOtherwiseClaim: "that the scan covered everything it looked at, omitting what it " +
			"hit and could not test",
	},
	{
		page:  "frontend/app/(app)/coverage/page.tsx",
		field: "untested_classes",
		wouldOtherwiseClaim: "that 'no findings' means nothing was there, when a whole class " +
			"(BOLA/BFLA needs two identities) was never reachable",
	},
	{
		page:  "frontend/app/(app)/coverage/page.tsx",
		field: "unattributable_from_our_tools",
		wouldOtherwiseClaim: "a clean bill of health over findings we are holding but could not " +
			"tie back to this asset",
	},
}

func TestCoverageClaimsRenderTheFieldsThatQualifyThem(t *testing.T) {
	const root = "../.."
	cache := map[string]string{}
	for _, r := range required {
		src, ok := cache[r.page]
		if !ok {
			b, err := os.ReadFile(root + "/" + r.page)
			if err != nil {
				// A renamed or moved page is a real signal, not a reason to skip: the guard
				// silently covering nothing is the bug one level up.
				t.Errorf("cannot read %s: %v — if the page moved, update this table rather than "+
					"letting the guard cover nothing", r.page, err)
				continue
			}
			src = string(b)
			cache[r.page] = src
		}
		// Word-boundary, not substring. A plain Contains passes on tools_failed_REMOVED,
		// which is precisely how a field gets renamed out of a page while its guard stays
		// green — the guard would then be one more thing that looks like it is checking.
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(r.field) + `\b`).MatchString(src) {
			t.Errorf("%s never references %q.\n\nWithout it the page asserts %s.\n\n"+
				"The backend computes this field and (for tools_failed) a Go test already asserts "+
				"it must not be folded into 'ran clean'. That test passes while the screen says the "+
				"opposite, which is why this guard is here and not there.",
				r.page, r.field, r.wouldOtherwiseClaim)
		}
	}
}


// A closed set declared in Go and mirrored by hand in TypeScript drifts in one direction: the Go
// side gains a member and the screen falls through to its raw enum slug.
//
// It had already drifted when this was written. tenanteval grew three sources —
// evidence_insufficient, accepted_risk and human_verdict — and the eval page still labelled the
// original three. The worst of them is human_verdict: that case exists BECAUSE someone typed an
// answer, so the page thanking them for it rendered "human_verdict" at them. A customer who takes
// the trouble to correct the product and is shown a database enum learns something true about how
// much their answer mattered.
//
// The repo already treats this as a real category — platformapi.AllDegradationKinds calls itself
// "the closed set, for the guard test and for the frontend's exhaustiveness". This is the same
// guarantee for the one other closed set a customer reads.
func TestEveryEvalCaseSourceHasACustomerFacingLabel(t *testing.T) {
	const page = "../../frontend/app/(app)/eval/page.tsx"
	b, err := os.ReadFile(page)
	if err != nil {
		t.Fatalf("cannot read %s: %v", page, err)
	}
	src := string(b)

	// The label map only, not the whole file: `f.source === "reinstated"` elsewhere would
	// otherwise satisfy the check while the label itself is missing.
	m := regexp.MustCompile(`(?s)const SOURCE_LABEL: Record<string, string> = \{(.*?)\n\};`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("SOURCE_LABEL not found in the eval page — if it was renamed, update this guard " +
			"rather than leaving it matching nothing")
	}
	labels := m[1]

	for _, s := range tenanteval.AllSources() {
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(string(s)) + `\s*:`).MatchString(labels) {
			t.Errorf("SOURCE_LABEL has no entry for %q, so the eval page renders that raw slug to "+
				"the customer.\n\nEvery entry in this map is a sentence about a decision THEY made; "+
				"an enum name in its place reads as a defect in the thing they just corrected.", s)
		}
	}
}
