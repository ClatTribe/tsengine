package training

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func mustComplete(t *testing.T, subject, mod string, tier Tier, provider, by string, at time.Time) Completion {
	t.Helper()
	c, err := NewCompletion(subject, mod, tier, provider, by, "", at, Default())
	if err != nil {
		t.Fatalf("NewCompletion(%s,%s,%s): %v", subject, mod, tier, err)
	}
	return c
}

// A completion citing a module nobody can read would put a curriculum entry in an audit report that
// does not exist. Refused at the constructor, so nothing downstream has to re-check it.
func TestCompletionRefusesAModuleThatDoesNotExist(t *testing.T) {
	_, err := NewCompletion("ada@acme.io", "advanced-cryptography", TierDelivered, "", "", "", now, Default())
	if !errors.Is(err, ErrUnknownModule) {
		t.Fatalf("want ErrUnknownModule, got %v", err)
	}
}

// An external attestation is a second-hand claim. Without the provider it cannot be checked, and
// without a recorder nobody stands behind it — the same rule every other attestation here follows.
func TestExternalCompletionRequiresAProviderAndARecorder(t *testing.T) {
	if _, err := NewCompletion("ada@acme.io", "phishing", TierAttested, "", "sec@acme.io", "", now, Default()); !errors.Is(err, ErrNoProvider) {
		t.Errorf("no provider: want ErrNoProvider, got %v", err)
	}
	if _, err := NewCompletion("ada@acme.io", "phishing", TierAttested, "KnowBe4", "", "", now, Default()); !errors.Is(err, ErrNoRecorder) {
		t.Errorf("no recorder: want ErrNoRecorder, got %v", err)
	}
	c, err := NewCompletion("ada@acme.io", "phishing", TierAttested, "KnowBe4", "sec@acme.io", "", now, Default())
	if err != nil {
		t.Fatalf("complete attestation refused: %v", err)
	}
	if c.Provider != "KnowBe4" || c.RecordedBy != "sec@acme.io" {
		t.Errorf("provider/recorder not kept: %+v", c)
	}
}

// A delivered completion is the product's OWN observation. Accepting a caller's claim about where
// the content came from would let the strongest tier carry someone else's word for it.
func TestDeliveredCompletionNamesThisProductAndNotTheCaller(t *testing.T) {
	c := mustComplete(t, "ada@acme.io", "phishing", TierDelivered, "Some Other Vendor", "someone", now)
	if c.Provider != SelfProvider {
		t.Errorf("delivered completion recorded provider %q; a delivered tier means WE showed it", c.Provider)
	}
	if c.RecordedBy != "" {
		t.Errorf("delivered completion recorded %q as the recorder; the subject confirmed it themselves", c.RecordedBy)
	}
}

func TestSubjectIsRequiredAndNormalised(t *testing.T) {
	if _, err := NewCompletion("   ", "phishing", TierDelivered, "", "", "", now, Default()); !errors.Is(err, ErrNoSubject) {
		t.Errorf("want ErrNoSubject, got %v", err)
	}
	c := mustComplete(t, "  Ada@Acme.IO ", "phishing", TierDelivered, "", "", now)
	if c.Subject != "ada@acme.io" {
		t.Errorf("subject %q not normalised — it is the key a roster row joins on", c.Subject)
	}
}

// An annual requirement met fourteen months ago is not met. Reporting it as current is the plainest
// version of the overclaim this package exists to prevent.
func TestACompletionOlderThanItsRecurrenceIsExpiredNotComplete(t *testing.T) {
	people := []Person{{Email: "ada@acme.io", Source: "hris"}}
	old := mustComplete(t, "ada@acme.io", "phishing", TierDelivered, "", "", now.AddDate(0, 0, -400))
	fresh := mustComplete(t, "ada@acme.io", "accounts", TierDelivered, "", "", now.AddDate(0, 0, -30))

	got := map[string]string{}
	for _, s := range Evaluate(Default(), people, []Completion{old, fresh}, now) {
		got[s.ModuleID] = s.State
	}
	if got["phishing"] != StateExpired {
		t.Errorf("400-day-old annual completion reads %q; want %q", got["phishing"], StateExpired)
	}
	if got["accounts"] != StateComplete {
		t.Errorf("30-day-old completion reads %q; want %q", got["accounts"], StateComplete)
	}
}

// Expired and outstanding are DIFFERENT problems: a refresher and an onboarding gap are chased
// differently, and merging them hides which one a person has.
func TestExpiredIsNotFoldedIntoOutstanding(t *testing.T) {
	people := []Person{{Email: "ada@acme.io", Source: "hris"}, {Email: "grace@acme.io", Source: "hris"}}
	comps := []Completion{mustComplete(t, "ada@acme.io", "phishing", TierDelivered, "", "", now.AddDate(0, 0, -400))}
	s := Summarize(Default(), people, Evaluate(Default(), people, comps, now))
	if s.Expired != 1 {
		t.Errorf("Expired = %d, want 1", s.Expired)
	}
	// grace has nothing at all; ada has four other modules untouched.
	if want := len(Default().Modules)*2 - 1; s.Outstanding != want {
		t.Errorf("Outstanding = %d, want %d", s.Outstanding, want)
	}
	if !strings.Contains(s.Detail, "never started") || !strings.Contains(s.Detail, "too long ago") {
		t.Errorf("detail does not distinguish the two open states: %q", s.Detail)
	}
}

// The newest completion decides currency. An old record must not out-vote a recent one just because
// it appears later in the slice.
func TestTheNewestCompletionWins(t *testing.T) {
	people := []Person{{Email: "ada@acme.io", Source: "hris"}}
	comps := []Completion{
		mustComplete(t, "ada@acme.io", "phishing", TierDelivered, "", "", now.AddDate(0, 0, -10)),
		mustComplete(t, "ada@acme.io", "phishing", TierAttested, "KnowBe4", "sec@acme.io", now.AddDate(0, 0, -500)),
	}
	for _, s := range Evaluate(Default(), people, comps, now) {
		if s.ModuleID != "phishing" {
			continue
		}
		if s.State != StateComplete || s.Tier != TierDelivered {
			t.Fatalf("stale record won: state=%s tier=%s", s.State, s.Tier)
		}
	}
}

// THE HEADLINE REFUSAL. One percentage over both tiers would rise as a customer evidenced less and
// asserted more. The two are counted separately and no combined figure is emitted at all.
func TestSummaryCountsTheTiersSeparatelyAndPublishesNoCombinedRate(t *testing.T) {
	people := []Person{{Email: "ada@acme.io", Source: "hris"}}
	var comps []Completion
	for i, m := range Default().Modules {
		tier, prov, by := TierDelivered, "", ""
		if i%2 == 1 {
			tier, prov, by = TierAttested, "KnowBe4", "sec@acme.io"
		}
		comps = append(comps, mustComplete(t, "ada@acme.io", m.ID, tier, prov, by, now.AddDate(0, 0, -5)))
	}
	s := Summarize(Default(), people, Evaluate(Default(), people, comps, now))
	if s.CompleteDelivered == 0 || s.CompleteAttested == 0 {
		t.Fatalf("tiers not both counted: %+v", s)
	}
	if s.CompleteDelivered+s.CompleteAttested != s.Assignments {
		t.Fatalf("counts do not add up: %+v", s)
	}
	// A structural check, not a stylistic one: if a Percent/Rate/Score field is ever added, this
	// package has started publishing the number it exists to refuse.
	for _, banned := range []string{"Percent", "Rate", "Score", "Compliance"} {
		if hasField(s, banned) {
			t.Errorf("Summary gained a %s field — a single figure spanning delivered and attested "+
				"evidence rises as a customer asserts more and evidences less, which is exactly what "+
				"this package refuses to publish", banned)
		}
	}
}

// With no roster there is no denominator. "Nothing outstanding" over nobody is not a trained
// workforce, and a reader skimming the counts must not be able to take it for one.
func TestAnEmptyRosterIsReportedAsAnAbsentDenominatorNotAsSuccess(t *testing.T) {
	s := Summarize(Default(), nil, Evaluate(Default(), nil, nil, now))
	if !s.NoRoster {
		t.Fatal("NoRoster is false with nobody on the roster")
	}
	if s.Assignments != 0 || s.Outstanding != 0 {
		t.Fatalf("counts invented over an empty roster: %+v", s)
	}
	low := strings.ToLower(s.Detail)
	if !strings.Contains(low, "not a trained workforce") {
		t.Errorf("detail does not refuse the reading it must refuse: %q", s.Detail)
	}
}

// The roster's SOURCE is part of the claim: an HRIS roster and this product's own user list are very
// different statements about who works here.
func TestRosterSourcesAreReported(t *testing.T) {
	people := []Person{{Email: "a@acme.io", Source: "hris"}, {Email: "b@acme.io", Source: "workspace_users"}}
	s := Summarize(Default(), people, Evaluate(Default(), people, nil, now))
	if len(s.RosterSources) != 2 {
		t.Fatalf("RosterSources = %v, want both sources named", s.RosterSources)
	}
}

// A roster row with no address can neither be matched to a completion nor asked to complete one.
// Counting it would inflate the outstanding column with rows nobody can action.
func TestARosterRowWithNoAddressIsNotAssigned(t *testing.T) {
	people := []Person{{Name: "No Address", Source: "hris"}}
	if got := Evaluate(Default(), people, nil, now); len(got) != 0 {
		t.Fatalf("assigned %d modules to a person with no email", len(got))
	}
}

// The content is what makes "delivered" mean anything. A module that ships empty is a checkbox
// producing an audit record, which is the one outcome this package must not have.
func TestEveryModuleHasRealContentAndARealControlNexus(t *testing.T) {
	for _, m := range Default().Modules {
		if len(m.Body) < 3 {
			t.Errorf("module %q has %d paragraphs — a delivered completion asserts the person was "+
				"shown something worth reading", m.ID, len(m.Body))
		}
		words := 0
		for _, p := range m.Body {
			words += len(strings.Fields(p))
		}
		if words < 150 {
			t.Errorf("module %q is %d words; too thin to claim anybody was trained by it", m.ID, words)
		}
		if m.RecurEveryDays <= 0 {
			t.Errorf("module %q never expires, so a completion from any date reads as current", m.ID)
		}
		if len(m.Controls) == 0 {
			t.Errorf("module %q maps to no control", m.ID)
		}
	}
	if len(Default().Modules) == 0 || Default().Version == "" {
		t.Fatal("the default curriculum is empty or unversioned")
	}
}
