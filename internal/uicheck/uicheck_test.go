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
	"path/filepath"
	"regexp"
	"strings"
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
		page:  "frontend/app/(app)/findings/[id]/page.tsx",
		field: "advisories",
		wouldOtherwiseClaim: "nothing at all, which is the problem — the vendor advisory is the page " +
			"that carries the patched version and the workaround, so a responder holding a KEV CVE " +
			"had to go and find it. CISA publishes the links with every KEV entry (3,023 live) and " +
			"the ingest was rescuing them from being discarded on the stated grounds of what a " +
			"responder sees; they then reached exactly one renderer, the agent's on-demand lookup " +
			"for CVEs that are NOT in the findings",
	},
	{
		page:  "frontend/app/(app)/findings/[id]/page.tsx",
		field: "weapon_rank",
		wouldOtherwiseClaim: "that every public exploit is equally usable — a Metasploit module ranked " +
			"excellent runs use/set/run and never crashes the service, one ranked manual may not work " +
			"at all, and both read as \"Public exploit available\". The corpus discriminates (live: " +
			"1,383 excellent against 78 manual) and the rank reached the L2 digest while the human " +
			"triaging the finding saw the same sentence either way",
	},
	{
		page:  "frontend/app/(app)/findings/[id]/page.tsx",
		field: "derived_from",
		wouldOtherwiseClaim: "a cross-surface finding as something observed, when nothing observed it — " +
			"it was DERIVED by joining other findings, and those ids are its entire evidence. Its own Go " +
			"doc says that without them it is \"an assertion with nothing behind it\", which is what the " +
			"page showed",
	},
	{
		page:  "frontend/app/(app)/incidents/page.tsx",
		field: "ransomware",
		wouldOtherwiseClaim: "a ransomware-linked incident as an ordinary one. CISA records this " +
			"separately from KEV BECAUSE it is a stronger claim — exploited in the wild versus " +
			"exploited by crews who encrypt the estate — and a queue showing neither is ranked by " +
			"severity alone, the number that knows least about who is using this",
	},
	{
		page:  "frontend/app/(app)/incidents/page.tsx",
		field: "kev_due_at",
		wouldOtherwiseClaim: "that no external deadline exists. CISA publishes a BOD 22-01 due date " +
			"and detect.go carries it VERBATIM rather than as a window from OpenedAt, precisely so a " +
			"customer is not told they have a fortnight when the government's answer is that they are " +
			"months late — showing nothing tells them less than either",
	},
	{
		page:  "frontend/app/(app)/issues/page.tsx",
		field: "data_tier",
		wouldOtherwiseClaim: "an ordering the reader cannot account for. The list is RE-SORTED by " +
			"risk_rank (severity x tier), so a Medium on a customer-data asset outranks a Medium " +
			"elsewhere — shown without the tier that is two Mediums in an unexplained order, and the " +
			"product knows exactly why",
	},
	{
		page:  "frontend/app/(app)/incidents/page.tsx",
		field: "kev_accelerated",
		wouldOtherwiseClaim: "an unexplained deadline — which is verbatim what the field's Go doc says " +
			"it exists to prevent (\"so the UI can say WHY the clock is short instead of showing an " +
			"unexplained deadline\"). SLABreach carries three such reasons and the TypeScript " +
			"interface declared none of them",
	},
	{
		page:  "frontend/app/(app)/incidents/page.tsx",
		field: "kev",
		wouldOtherwiseClaim: "a CISA deadline without being able to state the fact it follows from. " +
			"kev_due_at and ransomware were surfaced while the base known-exploited flag was still " +
			"undeclared",
	},
	{
		page:  "frontend/app/(app)/activity/page.tsx",
		field: "approver",
		wouldOtherwiseClaim: "a change to a customer's cloud with no sign of who authorised it. The " +
			"product's central invariant is that the only write path is reached AFTER a human decides " +
			"(§18.2 inv. 3) and that every decision is signed into the ledger (inv. 4) — so WHO decided " +
			"is the accountability record. It was stored and signed while no screen declared it",
	},
	{
		page:  "frontend/app/(app)/findings/[id]/page.tsx",
		field: "exploitability",
		wouldOtherwiseClaim: "a severity as the scanner's when it may be OURS. The L1.5 hook promotes " +
			"a critical-class CWE rated below high up to high on this basis, so the reader sees \"high\" " +
			"with no sign that we raised it or why — and §2.5 requires the L1 audience be able to audit " +
			"and override what the AI decided, which they cannot do with reasoning that is not shown",
	},
	{
		page:  "frontend/app/(app)/findings/[id]/page.tsx",
		field: "ssvc",
		wouldOtherwiseClaim: "that KEV and EPSS are all we know about exploitation. CISA's SSVC " +
			"Automatable point is the only signal separating a vulnerability exploited by hand against " +
			"one target from one that can be driven across an estate, and weapon_rank already reached " +
			"the L2 agent for months while the human saw nothing — repeating that would be the same " +
			"mistake twice",
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
		// Comments are STRIPPED before matching. A guard that reads prose can be satisfied by the
		// very comment explaining why the field matters — which is exactly what happened: the
		// approver entry passed while the code had been renamed out, because the sentence above it
		// said "approver". A check a comment can satisfy is a check that does not read code.
		if !readsField(stripComments(src), r.field) {
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

// A shared closed set must not be shadowed by a local copy.
//
// frontend/lib/frameworks.ts carries all 25 frameworks and its consistency with grc.Frameworks
// is already gated (grc.frameworks_e2e_test.go). That gate protects the shared map — it cannot
// see a PAGE that declares its own. The audits page did exactly that with six frameworks, so an
// engagement against any of the other nineteen rendered its raw key to the auditor reading it,
// while the framework mirror-consistency test passed.
//
// A local copy of a guarded set is worse than an unguarded set, because the guard's existence is
// what makes everyone stop looking.
func TestNoPageShadowsASharedClosedSet(t *testing.T) {
	shared := []struct{ name, owner string }{
		{"FRAMEWORK_LABEL", "@/lib/frameworks"},
		{"FRAMEWORK_DESC", "@/lib/frameworks"},
		{"FRAMEWORK_CATEGORY", "@/lib/frameworks"},
	}
	const root = "../../frontend"
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if err == nil && info.IsDir() && (info.Name() == "node_modules" || info.Name() == ".next") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".tsx") && !strings.HasSuffix(path, ".ts") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/lib/frameworks.ts") {
			return nil // the owner
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		src := string(b)
		for _, sh := range shared {
			if regexp.MustCompile(`const\s+` + sh.name + `\b`).MatchString(src) {
				offenders = append(offenders, path+" declares "+sh.name+" (owned by "+sh.owner+")")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("%d local copy/copies of a shared closed set:\n  %s\n\n"+
			"Import from the owning module. A local copy silently covers fewer members than the "+
			"shared one, and the guard on the shared map cannot see it — which is how six of "+
			"twenty-five frameworks reached an auditor-facing page while the mirror-consistency "+
			"test stayed green.", len(offenders), strings.Join(offenders, "\n  "))
	}
}

// readsField reports whether the page READS the field off an object — `x.field`, `x?.field`, or
// `x["field"]` — rather than merely containing the word.
//
// A bare word match is satisfied by things that are not consumption, and both bit this guard in one
// sitting: first the comment explaining why the field matters, then a local PARAMETER of the same
// name in the helper that formats it. Each time the guard passed while the code had been renamed
// out. The question it exists to ask is whether the page reads the API's field, and only property
// access answers it.
func readsField(src, field string) bool {
	q := regexp.QuoteMeta(field)
	return regexp.MustCompile(`\??\.\s*`+q+`\b`).MatchString(src) ||
		regexp.MustCompile(`\[\s*["'`+"`"+`]`+q+`["'`+"`"+`]\s*\]`).MatchString(src)
}

// stripComments removes // line comments and /* block */ comments (including JSX {/* … */}) so the
// field checks above match CODE rather than the prose describing it.
func stripComments(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); i++ {
		if src[i] == '/' && i+1 < len(src) {
			if src[i+1] == '/' {
				for i < len(src) && src[i] != '\n' {
					i++
				}
				b.WriteByte('\n')
				continue
			}
			if src[i+1] == '*' {
				i += 2
				for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
					i++
				}
				i++
				b.WriteByte(' ')
				continue
			}
		}
		b.WriteByte(src[i])
	}
	return b.String()
}
