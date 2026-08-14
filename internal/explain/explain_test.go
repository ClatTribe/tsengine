package explain

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func sqli() types.Finding {
	return types.Finding{
		ID: "f-1", RuleID: "nuclei::sqli-error-based", Tool: "nuclei",
		Severity: types.SeverityCritical, CWE: []string{"CWE-89"},
		Title: "SQL injection in search", Endpoint: "https://app.acme.com/search?q=",
	}
}

func kevListed(f types.Finding) types.Finding {
	f.ThreatIntel = &types.ThreatIntel{KEV: &types.KEVStatus{Listed: true, DateAdded: time.Now()}}
	return f
}

// ── THE READABILITY BAR ──────────────────────────────────────────────────────────────────────────
//
// The audience has no security engineer. If the readable surface carries jargon, it is not readable,
// and the whole package is decoration.

func TestExplain_NoJargonOnTheReadableSurface(t *testing.T) {
	e := Explain(sqli(), Context{AssetLabel: "your app"})
	surface := strings.ToLower(e.Headline + " " + e.What + " " + e.Why + " " + e.Fix)
	for _, jargon := range []string{"cwe-", "cve-", "nuclei::", "pattern_match", "l1.5"} {
		if strings.Contains(surface, jargon) {
			t.Errorf("readable surface leaks %q — the reader has nobody to translate it:\n%s", jargon, surface)
		}
	}
	// And the jargon must still be AVAILABLE, not deleted: a future security hire and the auditor
	// both want it.
	if e.Technical.RuleID == "" || len(e.Technical.CWE) == 0 {
		t.Error("technical detail was dropped rather than moved to the drill-down")
	}
}

func TestExplain_AnswersAllFourQuestions(t *testing.T) {
	e := Explain(sqli(), Context{})
	for name, got := range map[string]string{
		"headline": e.Headline, "what": e.What, "why": e.Why, "fix": e.Fix, "urgency": e.UrgencyLabel,
	} {
		if strings.TrimSpace(got) == "" {
			t.Errorf("%s is empty — the reader is left without one of the four answers", name)
		}
	}
}

// ── BLAST RADIUS: GRAPH OR SILENCE, NEVER BOILERPLATE ────────────────────────────────────────────

// The three states must read differently. Collapsing them is how a reader learns to discount every
// "why it matters" we ever print.
func TestExplain_BlastRadiusHasThreeDistinctStates(t *testing.T) {
	proven := Explain(sqli(), Context{Reaches: []string{"your customer table"}, ReachTraced: true}).Why
	traced := Explain(sqli(), Context{ReachTraced: true}).Why
	untraced := Explain(sqli(), Context{}).Why

	if !strings.Contains(proven, "customer table") {
		t.Errorf("a proven path did not name what it reaches: %q", proven)
	}
	if proven == traced || traced == untraced || proven == untraced {
		t.Errorf("the three blast-radius states are not distinct:\n proven:   %q\n traced:   %q\n untraced: %q",
			proven, traced, untraced)
	}
	// The untraced case must ADMIT it, not imply safety.
	if !strings.Contains(strings.ToLower(untraced), "not traced") {
		t.Errorf("an untraced finding did not admit the blast radius is unknown: %q", untraced)
	}
	// The traced-clean case must not read as "safe".
	if !strings.Contains(strings.ToLower(traced), "does not make it safe") {
		t.Errorf("a traced-clean finding read as safe: %q", traced)
	}
}

// ── URGENCY IS GROUNDED, NOT A SEVERITY LABEL ────────────────────────────────────────────────────

// THE ONE THAT MATTERS. Every scanner shouts CRITICAL, which is why nobody reads it. A severity label
// alone must never reach "fix today" — otherwise we have rebuilt the thing we are trying to replace.
func TestUrgency_SeverityAloneIsNeverUrgent(t *testing.T) {
	f := sqli() // critical, but no KEV, no proof, no attack, no reach
	e := Explain(f, Context{})
	if e.Urgency == UrgencyNow {
		t.Errorf("a bare CRITICAL severity was graded %q — that is the alert fatigue we exist to fix", e.Urgency)
	}
}

// Real evidence of exploitation DOES reach "now", and says why.
func TestUrgency_EvidenceOfExploitationIsUrgent(t *testing.T) {
	for name, tc := range map[string]struct {
		f   types.Finding
		ctx Context
	}{
		"on CISA KEV":       {kevListed(sqli()), Context{}},
		"under attack now":  {sqli(), Context{UnderAttack: true}},
		"proven on our box": {func() types.Finding { f := sqli(); f.VerificationStatus = types.VerificationVerified; return f }(), Context{}},
	} {
		e := Explain(tc.f, tc.ctx)
		if e.Urgency != UrgencyNow {
			t.Errorf("%s was graded %q, want now", name, e.Urgency)
		}
		if len(e.Because) == 0 {
			t.Errorf("%s gave no reason — an urgency the reader cannot check is just another label", name)
		}
	}
}

// The reasons must be facts the reader can verify, not restatements of the grade.
func TestUrgency_ReasonsAreCheckableFacts(t *testing.T) {
	e := Explain(kevListed(sqli()), Context{})
	joined := strings.ToLower(strings.Join(e.Because, " "))
	if !strings.Contains(joined, "cisa") {
		t.Errorf("the KEV reason does not name its source, so the reader cannot check it: %v", e.Because)
	}
}

// A low-severity finding with nothing behind it is honestly deprioritised — the other half of not
// crying wolf.
func TestUrgency_QuietFindingIsQuiet(t *testing.T) {
	f := sqli()
	f.Severity = types.SeverityLow
	f.CWE = []string{"CWE-200"}
	if e := Explain(f, Context{ReachTraced: true}); e.Urgency != UrgencyWhenever {
		t.Errorf("a low finding with no signal was graded %q", e.Urgency)
	}
}

// Reach + high severity escalates to this-week without needing exploitation evidence: proven access to
// something that matters is itself a reason to move, just not a reason to panic.
func TestUrgency_ReachEscalatesButNotToPanic(t *testing.T) {
	e := Explain(sqli(), Context{Reaches: []string{"your customer table"}, ReachTraced: true})
	if e.Urgency != UrgencyThisWeek {
		t.Errorf("high severity + a proven path to data was graded %q, want this_week", e.Urgency)
	}
}

// ── CLASS TRANSLATION ────────────────────────────────────────────────────────────────────────────

func TestClassify_TranslatesByCWEThenByKeyword(t *testing.T) {
	byCWE := Explain(sqli(), Context{})
	if !strings.Contains(strings.ToLower(byCWE.What), "database") {
		t.Errorf("CWE-89 was not translated: %q", byCWE.What)
	}
	// Same class, no CWE — the rule id must still route it.
	noCWE := sqli()
	noCWE.CWE = nil
	if got := Explain(noCWE, Context{}); !strings.Contains(strings.ToLower(got.What), "database") {
		t.Errorf("keyword fallback did not translate a sqli rule id: %q", got.What)
	}
}

// THE HONEST FALLBACK. For a class we do not model, we must report the tool's own words and SAY they
// are the tool's words — never generate a fluent paragraph we invented. A confident-sounding
// explanation of something we do not understand is the same failure as a hallucinated finding.
func TestClassify_UnknownClassAdmitsItIsUntranslated(t *testing.T) {
	f := types.Finding{
		ID: "f-x", RuleID: "obscure::thing", Tool: "sometool", Severity: types.SeverityMedium,
		Title: "Obscure protocol anomaly", Description: "The frobnicator emitted an unexpected value.",
	}
	e := Explain(f, Context{})
	low := strings.ToLower(e.What)
	if !strings.Contains(low, "scanner's own wording") && !strings.Contains(low, "do not have a plain-english translation") {
		t.Errorf("an unmodelled class was explained as if we understood it: %q", e.What)
	}
	if !strings.Contains(e.What, "Obscure protocol anomaly") {
		t.Error("the fallback dropped the tool's actual finding, leaving the reader with less than before")
	}
}

// ── DETERMINISM (the AI-off requirement) ─────────────────────────────────────────────────────────

// The package must be pure: same input, same output, no model, no clock. "Deterministic mode" cannot
// mean "unreadable mode".
func TestExplain_IsDeterministic(t *testing.T) {
	ctx := Context{Reaches: []string{"your customer table", "an admin identity"}, ReachTraced: true}
	first := fmt.Sprintf("%+v", Explain(sqli(), ctx))
	for i := 0; i < 5; i++ {
		if got := fmt.Sprintf("%+v", Explain(sqli(), ctx)); got != first {
			t.Fatalf("Explain is not deterministic:\n first: %s\n got:   %s", first, got)
		}
	}
}

func TestHumanList_ReadsLikeAPerson(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"a"}, "a"},
		{[]string{"b", "a"}, "a and b"},
		{[]string{"c", "a", "b"}, "a, b and c"},
	} {
		if got := humanList(tc.in); got != tc.want {
			t.Errorf("humanList(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExplain_HandlesEmptyFinding(t *testing.T) {
	e := Explain(types.Finding{}, Context{})
	if e.Headline == "" || e.What == "" {
		t.Error("an empty finding produced an empty explanation rather than an honest one")
	}
}

// ── TWO BUGS FOUND BY RUNNING IT, NOT BY UNIT TESTS ──────────────────────────────────────────────
//
// Both surfaced only in a live end-to-end run: a real Vercel snapshot through the real API produced
// output that was confidently wrong. Pinned here so they cannot come back.

// BUG 1: an assessor's "verified" is not an exploitation proof.
//
// vercelposture marks its findings VerificationVerified meaning "I read the configuration and it says
// this". explain read that as "we ran an exploit and it worked", and printed "Fix today — we proved it
// is exploitable on your system" over a Vercel setting nobody had attacked. Certainty about a fact is
// not evidence of exploitation, and this is exactly the overstatement the urgency ladder exists to
// prevent.
func TestUrgency_AssessorVerifiedIsNotAnExploitationProof(t *testing.T) {
	f := types.Finding{
		ID: "f-vp", RuleID: "vercel::preview-unprotected", Tool: "vercelposture",
		Severity: types.SeverityHigh, Title: "Preview deployments are public: acme-web",
		Description:        "Every pull request on acme-web publishes a preview URL that anyone can open. Turn on Deployment Protection for Preview in the project's settings.",
		VerificationStatus: types.VerificationVerified,
	}
	e := Explain(f, Context{})
	if e.Urgency == UrgencyNow {
		t.Errorf("a config assessor's finding was graded 'fix today' as if an exploit had been run: %v", e.Because)
	}
	for _, b := range e.Because {
		if strings.Contains(strings.ToLower(b), "proved it is exploitable") {
			t.Errorf("claimed exploitation proof for a config reading: %q", b)
		}
	}
}

// A pentest tool's "verified" DOES mean the exploit ran — that distinction is the whole point, so the
// other half is asserted too.
func TestUrgency_PentestVerifiedStillMeansProven(t *testing.T) {
	f := sqli()
	f.VerificationStatus = types.VerificationVerified
	if e := Explain(f, Context{}); e.Urgency != UrgencyNow {
		t.Errorf("a genuinely proven exploit was graded %q", e.Urgency)
	}
}

// BUG 2: an assessor's own prose must not be re-classified.
//
// Keyword-matching "production-secret-in-preview" landed on the hardcoded-credential template and told
// the reader to "move it to your secret manager" — it is already in one, scoped too broadly. A wrong
// diagnosis produces a wrong FIX, which is worse than no translation at all.
func TestClassify_AssessorProseIsNotReClassified(t *testing.T) {
	f := types.Finding{
		ID: "f-vp2", RuleID: "vercel::production-secret-in-preview", Tool: "vercelposture",
		Severity: types.SeverityHigh, Title: "Production secrets are available to preview builds: acme-web",
		Description: "On acme-web these variables are exposed to the preview environment as well as production: STRIPE_SECRET_KEY. Scope them to Production only, and give preview its own credentials.",
	}
	e := Explain(f, Context{})
	if strings.Contains(strings.ToLower(e.What), "written into the source") {
		t.Errorf("an env-var scoping finding was diagnosed as a hardcoded credential: %q", e.What)
	}
	if strings.Contains(strings.ToLower(e.Fix), "move it to your secret manager") {
		t.Errorf("the fix instructs a move that is already done — wrong diagnosis, wrong fix: %q", e.Fix)
	}
	// It must carry the assessor's OWN words, which were written for this reader.
	if !strings.Contains(e.What, "STRIPE_SECRET_KEY") {
		t.Errorf("the assessor's specifics were lost: %q", e.What)
	}
	if !strings.Contains(strings.ToLower(e.Fix), "scope them to production") {
		t.Errorf("the assessor's own remediation was not used as the fix: %q", e.Fix)
	}
}

// A raw scanner finding is still translated — the assessor rule must not disable classification
// generally.
func TestClassify_RawScannerIsStillTranslated(t *testing.T) {
	if e := Explain(sqli(), Context{}); !strings.Contains(strings.ToLower(e.What), "database") {
		t.Errorf("a raw nuclei finding stopped being translated: %q", e.What)
	}
}
