package recertify

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// An access review is audit evidence. That raises the bar on what "done" may mean: an auditor reads
// `complete: true` as "a named person examined everyone who had access, on this date". These tests
// hold the properties that make that reading true.

func at(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }

func fs() []types.Finding {
	return []types.Finding{
		{ID: "f1", RuleID: "operate::stale-account", Endpoint: "dormant@acme.io",
			Title: "Stale active account: dormant@acme.io", Severity: types.SeverityMedium},
		{ID: "f2", RuleID: "operate::stale-account", Endpoint: "ghost@acme.io",
			Title: "Stale active account: ghost@acme.io", Severity: types.SeverityHigh},
		{ID: "f3", RuleID: "operate::incomplete-offboarding", Endpoint: "ghost@acme.io",
			Title: "Suspended account still holds admin: ghost@acme.io", Severity: types.SeverityCritical},
		// Not an access question — must not pad the review.
		{ID: "f4", RuleID: "operate::dmarc-missing", Endpoint: "acme.io", Title: "No DMARC", Severity: types.SeverityHigh},
	}
}

// ── THE PROPERTY THAT MAKES IT EVIDENCE ──────────────────────────────────────────────────────────

// An EMPTY campaign is not a completed review. "0 of 0 reviewed, complete" would be filed as proof
// that access was examined, when nobody was examined at all — worse than having no artifact, because
// an auditor accepts it.
func TestEmptyCampaign_IsNotComplete(t *testing.T) {
	c, any := Build("c1", "t1", nil, at("2026-08-15T00:00:00Z"))
	if any {
		t.Error("an empty campaign reported that there was something to review")
	}
	p := Summarize(c)
	if p.Complete {
		t.Fatal("a campaign that examined nobody reported complete — that is an audit artifact " +
			"asserting a review which never happened")
	}
	if p.Total != 0 {
		t.Errorf("total = %d", p.Total)
	}
}

// A partly-finished review is not a review. An auditor asking "did you complete the access review"
// must get false until every person has a decision.
func TestPartialReview_IsNotComplete(t *testing.T) {
	c, _ := Build("c1", "t1", fs(), at("2026-08-15T00:00:00Z"))
	if !Decide(&c, "dormant@acme.io", DecisionKeep, "cto@acme.io", "", at("2026-08-15T01:00:00Z")) {
		t.Fatal("a valid decision was refused")
	}
	p := Summarize(c)
	if p.Complete {
		t.Fatalf("1 of %d reviewed reported complete", p.Total)
	}
	if p.Pending != 1 || p.Reviewed != 1 {
		t.Errorf("progress = %+v", p)
	}
}

// And it IS complete once everyone has a decision — the guard must not be unsatisfiable.
func TestFullReview_IsComplete(t *testing.T) {
	c, _ := Build("c1", "t1", fs(), at("2026-08-15T00:00:00Z"))
	for _, s := range []string{"dormant@acme.io", "ghost@acme.io"} {
		Decide(&c, s, DecisionKeep, "cto@acme.io", "", at("2026-08-15T01:00:00Z"))
	}
	if p := Summarize(c); !p.Complete {
		t.Fatalf("every identity decided but not complete: %+v", p)
	}
}

// ── ATTRIBUTION ──────────────────────────────────────────────────────────────────────────────────

// An unattributed decision cannot be evidence — the entire point is that a NAMED person stood behind
// it. Recording one anonymously would produce an artifact no auditor should accept and we would.
func TestDecision_RequiresANamedReviewer(t *testing.T) {
	c, _ := Build("c1", "t1", fs(), at("2026-08-15T00:00:00Z"))
	if Decide(&c, "ghost@acme.io", DecisionKeep, "", "", at("2026-08-15T01:00:00Z")) {
		t.Fatal("a decision with nobody's name on it was accepted")
	}
	if Decide(&c, "ghost@acme.io", DecisionKeep, "   ", "", at("2026-08-15T01:00:00Z")) {
		t.Error("a whitespace reviewer name was accepted")
	}
	if p := Summarize(c); p.Reviewed != 0 {
		t.Errorf("an unattributed decision was counted: %+v", p)
	}
}

// The reviewer and the date are recorded, because that is what the evidence consists of.
func TestDecision_RecordsWhoAndWhen(t *testing.T) {
	c, _ := Build("c1", "t1", fs(), at("2026-08-15T00:00:00Z"))
	Decide(&c, "ghost@acme.io", DecisionRevoke, "cto@acme.io", "left in June", at("2026-08-15T09:30:00Z"))
	for _, i := range c.Identities {
		if i.Subject != "ghost@acme.io" {
			continue
		}
		if i.DecidedBy != "cto@acme.io" || i.DecidedAt == "" {
			t.Errorf("who/when not recorded: %+v", i)
		}
		if i.Note != "left in June" {
			t.Errorf("the reviewer's reasoning was dropped: %q", i.Note)
		}
	}
}

// An invalid verdict is refused rather than stored as a third state nobody defined.
func TestDecision_RefusesUnknownVerdict(t *testing.T) {
	c, _ := Build("c1", "t1", fs(), at("2026-08-15T00:00:00Z"))
	if Decide(&c, "ghost@acme.io", Decision("maybe"), "cto@acme.io", "", time.Now()) {
		t.Error("an undefined verdict was accepted")
	}
}

// ── WHAT GOES INTO THE REVIEW ────────────────────────────────────────────────────────────────────

// Only ACCESS questions. A review padded with every finding about a person becomes a second findings
// list, and reviewers stop reading it — which costs more than the rows it adds.
func TestBuild_OnlyIncludesAccessQuestions(t *testing.T) {
	c, _ := Build("c1", "t1", fs(), at("2026-08-15T00:00:00Z"))
	for _, i := range c.Identities {
		if i.Subject == "acme.io" {
			t.Error("a DMARC finding put a DOMAIN into an access review")
		}
	}
	if len(c.Identities) != 2 {
		t.Fatalf("expected 2 people, got %d: %+v", len(c.Identities), c.Identities)
	}
}

// One row per person, carrying every reason. A reviewer deciding about someone should see all of it
// at once, not the same person three times.
func TestBuild_GroupsBySubjectAndKeepsEveryReason(t *testing.T) {
	c, _ := Build("c1", "t1", fs(), at("2026-08-15T00:00:00Z"))
	var ghost *Identity
	for i := range c.Identities {
		if c.Identities[i].Subject == "ghost@acme.io" {
			ghost = &c.Identities[i]
		}
	}
	if ghost == nil {
		t.Fatal("ghost@acme.io missing")
	}
	if len(ghost.Reasons) != 2 || len(ghost.FindingIDs) != 2 {
		t.Errorf("reasons/findings lost: %+v", ghost)
	}
	// Worst severity wins, so the list leads with what matters.
	if ghost.Severity != types.SeverityCritical {
		t.Errorf("severity = %q, want critical (the offboarding finding)", ghost.Severity)
	}
	if c.Identities[0].Subject != "ghost@acme.io" {
		t.Errorf("the worst case is not first: %v", c.Identities[0].Subject)
	}
}

// A finding that names nobody cannot be reviewed — there is no person to decide about. It is dropped
// rather than shown as a row no reviewer can action.
func TestBuild_DropsFindingsWithNoSubject(t *testing.T) {
	c, any := Build("c1", "t1", []types.Finding{
		{ID: "x", RuleID: "operate::stale-account", Endpoint: "", Title: "Stale account"},
	}, at("2026-08-15T00:00:00Z"))
	if any || len(c.Identities) != 0 {
		t.Errorf("a subjectless finding became a review row: %+v", c.Identities)
	}
}

// ── A REVIEW IS A DECISION, NOT AN ACTION ────────────────────────────────────────────────────────

// Deciding "revoke" must not revoke anything here. It yields the list for the normal remediation
// gate — a review click silently mutating a customer's IdP is authority this product does not take.
func TestRevoke_ProducesWorkRatherThanActing(t *testing.T) {
	c, _ := Build("c1", "t1", fs(), at("2026-08-15T00:00:00Z"))
	Decide(&c, "ghost@acme.io", DecisionRevoke, "cto@acme.io", "", at("2026-08-15T01:00:00Z"))
	Decide(&c, "dormant@acme.io", DecisionKeep, "cto@acme.io", "", at("2026-08-15T01:00:00Z"))

	rev := Revocations(c)
	if len(rev) != 1 || rev[0].Subject != "ghost@acme.io" {
		t.Fatalf("revocations = %+v, want just ghost@acme.io", rev)
	}
	// The finding ids travel with it, so the remediation the gate approves can cite its evidence.
	if len(rev[0].FindingIDs) == 0 {
		t.Error("a revocation carries no finding ids, so the resulting action could not cite why")
	}
}
