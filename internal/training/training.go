// Package training is the security-awareness training record: who was trained, on what, when,
// and on what evidence.
//
// # The gap this closes
//
// SOC 2 CC1.4 and CC2.2, ISO 27001 A.6.3 and PCI 12.6 all ask the same question, and it is not a
// question about infrastructure: were the people who work here trained on security? Every
// competitor in this category ships it. tsengine could evidence a great deal about machines and
// nothing at all about people — a policy-acknowledgement set (internal/grc/program.go) and, since
// the HRIS join, a roster. Training did not exist.
//
// # The refusal that shapes this package
//
// We are not a training-content company, and a completion record for a module nobody read is
// compliance theatre: it manufactures precisely the false confidence that is worse than not
// building the feature at all. So a completion carries the EVIDENCE TIER that produced it, and the
// two tiers are never merged:
//
//   - TierDelivered — the content was rendered in THIS product and the person confirmed it at a
//     recorded time. We know they were shown it. That is the strongest claim software can make
//     without proctoring an exam, which is why the status is "completed" and never "passed".
//   - TierAttested — they were trained somewhere else (a vendor course, an internal deck, a live
//     session) and someone recorded that fact, NAMING the provider and the person who recorded it.
//     It is a second-hand claim and is rendered as one.
//
// Summarize therefore emits the tiers SEPARATELY and NO combined percentage. A single "92%
// trained" figure spanning both would RISE as a customer asserted more and evidenced less — the
// same defect internal/ctoreadiness and the security questionnaire each refuse by name.
//
// # Grounding (§10)
//
//   - A completion for a module that does not exist is REFUSED, not stored. Otherwise the report
//     cites a curriculum entry nobody can read.
//   - An attested completion with no named provider or no named recorder is REFUSED, for the same
//     reason every other attestation in this codebase requires a name: an unattributed claim is a
//     log line, not evidence.
//   - A completion older than the module's recurrence is EXPIRED, not complete. An annual
//     requirement met fourteen months ago is not met, and reporting it as current is the plainest
//     form of the overclaim this file exists to prevent.
//   - The ROSTER is the denominator, and with no roster there is no denominator. "12 of 12 trained"
//     over the twelve people we happen to know about, at a company of forty, is a false all-clear —
//     so Summarize reports NoRoster rather than a percentage over a set it cannot size.
package training

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Tier is how we know a person was trained. The two are not interchangeable and are never summed.
type Tier string

const (
	// TierDelivered — rendered in this product, confirmed by the person, at a recorded time.
	TierDelivered Tier = "delivered"
	// TierAttested — completed elsewhere; someone recorded it, naming the provider.
	TierAttested Tier = "attested_external"
)

func (t Tier) Valid() bool { return t == TierDelivered || t == TierAttested }

var (
	// ErrUnknownModule refuses a completion citing a module that is not in the curriculum.
	ErrUnknownModule = errors.New("training: no such module")
	// ErrNoSubject refuses a completion that names nobody.
	ErrNoSubject = errors.New("training: a completion must name the person it is for")
	// ErrNoProvider refuses an external attestation that does not say who delivered the training.
	ErrNoProvider = errors.New("training: an external completion must name the provider that delivered it")
	// ErrNoRecorder refuses an external attestation nobody stands behind.
	ErrNoRecorder = errors.New("training: an external completion must name who recorded it")
	// ErrBadTier refuses an evidence tier that is not one of the two.
	ErrBadTier = errors.New(`training: tier must be "delivered" or "attested_external"`)
)

// Completion is one person finishing one module, once.
type Completion struct {
	// Subject is the person, by the email their identity provider knows them as — the same key the
	// HRIS join matches on, so a roster row and a training record refer to the same human.
	Subject  string    `json:"subject"`
	ModuleID string    `json:"module_id"`
	Tier     Tier      `json:"tier"`
	At       time.Time `json:"at"`
	// Provider names who delivered it. For TierDelivered it is this product; for TierAttested it is
	// required, because "trained externally" without naming the source is not a fact anyone can check.
	Provider string `json:"provider,omitempty"`
	// RecordedBy is the human who entered an external attestation. Empty for TierDelivered, where the
	// subject confirmed it themselves and the product observed it.
	RecordedBy string `json:"recorded_by,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Person is someone who is expected to complete the curriculum.
type Person struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
	// Source says where we learned this person exists — the HRIS roster, or the workspace's own user
	// list. Rendered, because a roster from an HRIS is a very different denominator from the handful
	// of people who happen to have logged into this product.
	Source string `json:"source"`
}

// NewCompletion validates a completion before it is stored. It is the only constructor: the refusals
// belong at the boundary, so a stored record is one the report can cite without re-checking it.
func NewCompletion(subject, moduleID string, tier Tier, provider, recordedBy, note string, now time.Time, c Curriculum) (Completion, error) {
	subject = strings.ToLower(strings.TrimSpace(subject))
	if subject == "" {
		return Completion{}, ErrNoSubject
	}
	if !tier.Valid() {
		return Completion{}, ErrBadTier
	}
	m, ok := c.Module(moduleID)
	if !ok {
		return Completion{}, fmt.Errorf("%w: %q", ErrUnknownModule, moduleID)
	}
	provider = strings.TrimSpace(provider)
	recordedBy = strings.TrimSpace(recordedBy)
	if tier == TierAttested {
		if provider == "" {
			return Completion{}, ErrNoProvider
		}
		if recordedBy == "" {
			return Completion{}, ErrNoRecorder
		}
	} else {
		// A delivered completion is the product's own observation, so it names the product rather
		// than accepting a caller's word for where the content came from.
		provider = SelfProvider
		recordedBy = ""
	}
	return Completion{
		Subject: subject, ModuleID: m.ID, Tier: tier, At: now.UTC(),
		Provider: provider, RecordedBy: recordedBy, Note: strings.TrimSpace(note),
	}, nil
}

// SelfProvider is the provider recorded for content this product delivered.
const SelfProvider = "TensorShield"

// Status is where one person stands on one module.
type Status struct {
	Subject  string `json:"subject"`
	Name     string `json:"name,omitempty"`
	ModuleID string `json:"module_id"`
	Title    string `json:"title"`
	// State is one of StateComplete | StateExpired | StateOutstanding.
	State string `json:"state"`
	// Tier and At describe the completion behind a complete or expired state. Empty when outstanding —
	// there is nothing to describe.
	Tier      Tier      `json:"tier,omitempty"`
	At        time.Time `json:"at,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

const (
	// StateComplete — completed within the module's recurrence window.
	StateComplete = "complete"
	// StateExpired — completed, but longer ago than the recurrence allows. DISTINCT from outstanding:
	// one person has done this before and is due again, the other never has, and an onboarding gap and
	// a refresher gap are different problems for whoever has to chase them.
	StateExpired = "expired"
	// StateOutstanding — no completion on record.
	StateOutstanding = "outstanding"
)

// Evaluate resolves each (person, module) pair against the completions on record.
//
// The newest completion for a pair wins; older ones are history, not evidence of currency.
func Evaluate(c Curriculum, people []Person, comps []Completion, now time.Time) []Status {
	newest := map[string]Completion{}
	for _, cp := range comps {
		k := strings.ToLower(strings.TrimSpace(cp.Subject)) + "\x00" + cp.ModuleID
		if prev, ok := newest[k]; !ok || cp.At.After(prev.At) {
			newest[k] = cp
		}
	}

	var out []Status
	for _, p := range people {
		email := strings.ToLower(strings.TrimSpace(p.Email))
		if email == "" {
			// A roster row with no address cannot be matched to a completion or asked to complete one.
			// Counting it would inflate the outstanding column with rows nobody can action.
			continue
		}
		for _, m := range c.Modules {
			s := Status{Subject: email, Name: p.Name, ModuleID: m.ID, Title: m.Title, State: StateOutstanding}
			if cp, ok := newest[email+"\x00"+m.ID]; ok {
				s.Tier, s.At, s.Provider = cp.Tier, cp.At, cp.Provider
				s.ExpiresAt = cp.At.AddDate(0, 0, m.RecurEveryDays)
				if now.Before(s.ExpiresAt) {
					s.State = StateComplete
				} else {
					s.State = StateExpired
				}
			}
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].ModuleID < out[j].ModuleID
	})
	return out
}

// Summary is the honest state of the programme. Note what is NOT here: a single completion
// percentage. Delivered and attested evidence are different claims, and one number over both rises
// as a customer evidences less and asserts more.
type Summary struct {
	People  int `json:"people"`
	Modules int `json:"modules"`
	// Assignments is People × Modules — the denominator, stated so the counts below can be read
	// without recomputing it.
	Assignments int `json:"assignments"`

	// The two tiers, counted separately and deliberately never summed into a headline figure.
	CompleteDelivered int `json:"complete_delivered"`
	CompleteAttested  int `json:"complete_attested"`
	Expired           int `json:"expired"`
	Outstanding       int `json:"outstanding"`

	// NoRoster is true when we do not know who works here. It is NOT the same as "nobody is trained":
	// with no roster there is no denominator, and a completion rate over the handful of people we
	// happen to know about is a false all-clear at a company larger than that handful.
	NoRoster bool `json:"no_roster"`
	// RosterSources names where the roster came from, because an HRIS roster and this product's own
	// user list are very different claims about completeness.
	RosterSources []string `json:"roster_sources,omitempty"`
	// Detail states in words what the numbers mean, so a reader skimming cannot take an empty
	// programme for a finished one.
	Detail string `json:"detail"`
}

// Summarize counts the statuses. `people` is passed separately so an empty roster is reported as an
// absent denominator rather than as a programme with nothing outstanding.
func Summarize(c Curriculum, people []Person, sts []Status) Summary {
	s := Summary{People: len(people), Modules: len(c.Modules)}
	seen := map[string]bool{}
	for _, p := range people {
		if src := strings.TrimSpace(p.Source); src != "" && !seen[src] {
			seen[src] = true
			s.RosterSources = append(s.RosterSources, src)
		}
	}
	sort.Strings(s.RosterSources)

	for _, st := range sts {
		s.Assignments++
		switch st.State {
		case StateComplete:
			if st.Tier == TierAttested {
				s.CompleteAttested++
			} else {
				s.CompleteDelivered++
			}
		case StateExpired:
			s.Expired++
		default:
			s.Outstanding++
		}
	}

	s.NoRoster = len(people) == 0
	s.Detail = detail(s)
	return s
}

func detail(s Summary) string {
	switch {
	case s.NoRoster:
		return "Nobody is on the roster yet, so there is no training programme to report on — this is " +
			"not a trained workforce. Connect an HRIS, or invite your team, and everyone who works here " +
			"appears with what they still owe."
	case s.Outstanding == 0 && s.Expired == 0:
		return fmt.Sprintf("Every one of the %d assignments across %d people is current: %d confirmed in "+
			"this product and %d recorded as completed elsewhere. The two are counted separately because "+
			"they are different evidence.", s.Assignments, s.People, s.CompleteDelivered, s.CompleteAttested)
	default:
		return fmt.Sprintf("%d of %d assignments are still open — %d never started and %d completed too "+
			"long ago to still count. Of those that are current, %d were confirmed in this product and %d "+
			"were recorded as completed elsewhere.",
			s.Outstanding+s.Expired, s.Assignments, s.Outstanding, s.Expired, s.CompleteDelivered, s.CompleteAttested)
	}
}
