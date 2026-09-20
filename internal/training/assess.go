package training

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// assess.go turns the programme into findings, so training is EVIDENCE rather than a page.
//
// Without this the compliance layer could not see training at all: a control gap is opened by a real
// finding citing it (§18.2 inv. 5), so a workforce that had done nothing would look exactly like one
// that was fully trained. That is the false-compliant mode the whole coverage layer exists to
// prevent, and it is why the questionnaire's training question could not be promoted to the observed
// tier until this existed.
//
// ONE FINDING PER PERSON, not per assignment. Five modules across forty people is two hundred rows,
// and an issues list that size trains people to ignore it — the unit anyone actually acts on is "this
// person owes their training", so that is the unit reported.
//
// SEVERITY IS MEDIUM, deliberately. This is a control gap, not an exploitable weakness: nothing about
// an untrained colleague can be attacked directly, and opening an incident (high and above) for it
// would page someone at night over a training reminder.

// RuleOutstanding is the finding raised for a person who owes training.
const RuleOutstanding = "training::incomplete"

// Assess reports, per person, the modules they still owe. A fully-trained roster yields ZERO
// findings — and so does an EMPTY roster, which is why the caller must also stamp that the
// assessment ran: nothing found and nothing to look at must not read the same (§10).
func Assess(sts []Status, now time.Time) []types.Finding {
	type owed struct {
		name              string
		never, lapsed     []string
		earliestExpiredAt time.Time
	}
	by := map[string]*owed{}
	order := []string{}
	for _, s := range sts {
		if s.State == StateComplete {
			continue
		}
		o, ok := by[s.Subject]
		if !ok {
			o = &owed{name: s.Name}
			by[s.Subject] = o
			order = append(order, s.Subject)
		}
		if s.State == StateExpired {
			o.lapsed = append(o.lapsed, s.Title)
			if o.earliestExpiredAt.IsZero() || s.ExpiresAt.Before(o.earliestExpiredAt) {
				o.earliestExpiredAt = s.ExpiresAt
			}
			continue
		}
		o.never = append(o.never, s.Title)
	}
	sort.Strings(order)

	out := make([]types.Finding, 0, len(order))
	for _, subject := range order {
		o := by[subject]
		sort.Strings(o.never)
		sort.Strings(o.lapsed)
		who := subject
		if o.name != "" {
			who = o.name + " (" + subject + ")"
		}
		out = append(out, types.Finding{
			RuleID: RuleOutstanding,
			Tool:   "training",
			// The person IS the endpoint, so the dedup key (rule|endpoint) is stable across passes:
			// one row per person that closes when they finish, rather than a new row every scan.
			Endpoint:        subject,
			Severity:        types.SeverityMedium,
			Title:           title(o.never, o.lapsed, who),
			Description:     describe(o.never, o.lapsed, who, o.earliestExpiredAt, now),
			MITRETechniques: []string{"T1566"}, // phishing — what awareness training is chiefly a control against
			DiscoveredAt:    now.UTC(),
			Compliance:      complianceForTraining(),
		})
	}
	return out
}

func title(never, lapsed []string, who string) string {
	switch {
	case len(never) > 0 && len(lapsed) > 0:
		return fmt.Sprintf("%s has %d security training %s outstanding and %d lapsed",
			who, len(never), plural2(len(never), "module", "modules"), len(lapsed))
	case len(lapsed) > 0:
		return fmt.Sprintf("%s has %d lapsed security training %s",
			who, len(lapsed), plural2(len(lapsed), "module", "modules"))
	default:
		return fmt.Sprintf("%s has not completed %d security training %s",
			who, len(never), plural2(len(never), "module", "modules"))
	}
}

func describe(never, lapsed []string, who string, earliest time.Time, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is on the roster and is expected to complete the security-awareness curriculum. ", who)
	if len(never) > 0 {
		fmt.Fprintf(&b, "Not started: %s. ", strings.Join(never, ", "))
	}
	if len(lapsed) > 0 {
		// The lapse DATE is the substance for the reader: "overdue" is a state, "overdue since March"
		// is a fact somebody can act on and an auditor can check.
		fmt.Fprintf(&b, "Completed too long ago to still count: %s", strings.Join(lapsed, ", "))
		if !earliest.IsZero() {
			fmt.Fprintf(&b, " (due again since %s, %d days)", earliest.Format("2 January 2006"),
				int(now.Sub(earliest).Hours()/24))
		}
		b.WriteString(". ")
	}
	b.WriteString("Training completed elsewhere can be recorded against this person instead; it is " +
		"counted separately as second-hand evidence.")
	return b.String()
}

// complianceForTraining is the awareness-training control nexus, inline like every other
// posture assessor (§8 emission path). It is the SAME set the curriculum modules carry, because it
// is the same claim from the other direction: the module says which control it speaks to, and the
// finding says which control the gap affects.
func complianceForTraining() *types.Compliance {
	c := awarenessControls()
	return &types.Compliance{
		SOC2:       c["soc2"],
		ISO27001:   c["iso27001"],
		PCI:        c["pci"],
		HIPAA:      c["hipaa"],
		NIST80053:  c["nist_800_53"],
		NIST800171: c["nist_800_171"],
		CISv8:      c["cis_v8"],
	}
}

// RosterFrom assembles the people expected to complete the curriculum from the two sources the
// platform has. It lives here rather than in a handler because BOTH the API and the monitoring pass
// need exactly the same answer — two copies would eventually disagree about who works at a company,
// and the roster is the denominator under every number the programme reports.
//
// Only ACTIVE employees are assigned: someone who has left does not owe training, and listing them
// fills the outstanding column with people nobody can chase. The HRIS record wins on a duplicate —
// both describe the same human, but the HRIS knows their name and their employment status while the
// user table knows only that they logged in.
func RosterFrom(emps []platform.Employee, users []platform.User) []Person {
	byEmail := map[string]Person{}
	for _, e := range emps {
		if e.Status != platform.EmploymentActive {
			continue
		}
		if email := strings.ToLower(strings.TrimSpace(e.WorkEmail)); email != "" {
			byEmail[email] = Person{Email: email, Name: e.Name, Source: SourceHRIS}
		}
	}
	for _, u := range users {
		email := strings.ToLower(strings.TrimSpace(u.Email))
		if email == "" {
			continue
		}
		if _, ok := byEmail[email]; ok {
			continue
		}
		byEmail[email] = Person{Email: email, Name: u.Name, Source: SourceApp}
	}
	out := make([]Person, 0, len(byEmail))
	for _, p := range byEmail {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}

// The roster sources, named because an HRIS roster and "people who have logged into this product"
// are very different claims about who works at a company.
const (
	SourceHRIS = "hris"
	SourceApp  = "workspace_users"
)
