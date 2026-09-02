// Package hris is the JOINER / LEAVER join — employment records from the tenant's HR system
// correlated against the accounts its identity provider holds.
//
// # The gap this closes
//
// docs/integrations.md §3.2 called HRIS "the one thing we have nothing for", and the reason it
// matters is what an auditor asks for FIRST: was access granted when someone started, and removed
// when they left (SOC 2 CC1.4, CC6.2, CC6.3). internal/operate can see ACCOUNTS — who has one, who
// is admin, who has not logged in — but not EMPLOYMENT, so it cannot tell a contractor from a leaver
// from a service account. A stale-account check catches a leaver only once their account has been
// idle for ninety days; by then the offboarding failure is three months old. This package catches it
// the day HR records the departure.
//
// # Two sources, one deterministic join
//
// Fetchers read Merge.dev and Finch — unified HRIS APIs, because one integration each covers most of
// the market and building fifty individual ones is the wrong shape for this team (§4 of the same
// doc). The join itself is pure and provider-agnostic: Correlate takes the stored roster and the
// operate.Workspace the runner already fetches every pass, and returns findings.
//
// # Grounding (§10), stated as refusals
//
//   - Identity is matched on EMAIL EQUALITY ONLY, against addresses the HRIS itself asserts belong
//     to the person (work email, plus any personal addresses it lists). No name matching, no
//     domain guessing: a wrong merge here sends someone to suspend the account of a person who
//     still works there, and the shape of that mistake is the one estateingest/ghidentity refuses.
//   - "Terminated" comes from the HRIS's own status, or from an end date it recorded that has
//     passed. A future end date is a scheduled departure, not a leaver.
//   - An account with no HR record is reported at LOW as exactly that — "no record" — never as
//     rogue. Service accounts and shared mailboxes legitimately have none; the finding asks for an
//     owner to be recorded, which is what CC6.1 wants anyway.
//   - An empty roster correlates against nothing and says so in ChecksNotRun. Zero findings over
//     zero employees is not a clean offboarding process.
package hris

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Fetcher pulls the live employee roster from one HRIS.
type Fetcher interface {
	Fetch(ctx context.Context) ([]platform.Employee, FetchReport, error)
}

// FetchReport says what a fetch could and could not read.
type FetchReport struct {
	Provider  string `json:"provider"`
	Employees int    `json:"employees"`
	// Unread names records the directory listed but whose detail (emails, dates) could not be
	// read. They are kept in the roster with what is known, so a leaver is not silently dropped —
	// but they cannot be matched to an account without an address, and the name says so.
	Unread []string `json:"unread,omitempty"`
	// WithoutEmail counts records that carried no address at all. Nothing can be joined to them.
	WithoutEmail int `json:"without_email,omitempty"`
}

// Providers is the set of HRIS sources a config may name.
func Providers() []string { return []string{platform.HRISMerge, platform.HRISFinch} }

// ValidProvider reports whether p names a fetcher this package has.
func ValidProvider(p string) bool {
	for _, q := range Providers() {
		if q == p {
			return true
		}
	}
	return false
}

// Options are what a fetcher needs beyond its config.
type Options struct {
	Open func(ref string) (string, error)
	HTTP *http.Client
	// MergeBase / FinchBase override the provider endpoints (tests, regional deployments).
	MergeBase string
	FinchBase string
	Now       func() time.Time
}

// New builds the fetcher a tenant's HRISConfig describes, refusing one it cannot authenticate with.
func New(cfg *platform.HRISConfig, o Options) (Fetcher, error) {
	if cfg == nil {
		return nil, fmt.Errorf("hris: no employment-records source configured")
	}
	open := o.Open
	if open == nil {
		open = func(string) (string, error) { return "", fmt.Errorf("hris: no secret store to open credentials") }
	}
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	now := o.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	switch cfg.Provider {
	case platform.HRISMerge:
		if cfg.KeyRef == "" || cfg.AccountTokenRef == "" {
			return nil, fmt.Errorf("hris: merge needs the API key and the linked-account token")
		}
		key, err := open(cfg.KeyRef)
		if err != nil || key == "" {
			return nil, fmt.Errorf("hris: could not open the Merge API key")
		}
		acct, err := open(cfg.AccountTokenRef)
		if err != nil || acct == "" {
			return nil, fmt.Errorf("hris: could not open the Merge linked-account token")
		}
		base := cfg.BaseURL
		if base == "" {
			base = o.MergeBase
		}
		return &Merge{BaseURL: base, APIKey: key, AccountToken: acct, HTTP: hc, Now: now}, nil
	case platform.HRISFinch:
		if cfg.KeyRef == "" {
			return nil, fmt.Errorf("hris: finch needs the employer access token")
		}
		tok, err := open(cfg.KeyRef)
		if err != nil || tok == "" {
			return nil, fmt.Errorf("hris: could not open the Finch access token")
		}
		base := cfg.BaseURL
		if base == "" {
			base = o.FinchBase
		}
		return &Finch{BaseURL: base, Token: tok, HTTP: hc, Now: now}, nil
	}
	return nil, fmt.Errorf("hris: unknown provider %q", cfg.Provider)
}

// --- the join ---

// CorrelateOptions tunes the join.
type CorrelateOptions struct {
	Now   func() time.Time
	NewID func() string
}

// Report is what the join saw. It rides beside the findings so "zero findings" can be read
// correctly: over an empty roster it means nothing; over a matched one it means offboarding works.
type Report struct {
	Employees  int `json:"employees"`
	Terminated int `json:"terminated"`
	Accounts   int `json:"accounts"`
	// Matched counts accounts that resolved to an HR record by an asserted address.
	Matched int `json:"matched"`
	// Unmatched counts ACTIVE accounts with no HR record (each is a low finding).
	Unmatched int `json:"unmatched"`
	// LeaversWithAccess counts terminated employees whose account is still enabled (each a finding).
	LeaversWithAccess int `json:"leavers_with_access"`
	// LeaversDeprovisioned counts terminated employees whose account is suspended or gone — the
	// evidence that offboarding WORKED, which an auditor wants to see as much as the failures.
	LeaversDeprovisioned int `json:"leavers_deprovisioned"`
	// ChecksNotRun says, in words, why the join could not conclude something.
	ChecksNotRun []string `json:"checks_not_run,omitempty"`
}

// Correlate joins the stored roster against the identity provider's accounts.
func Correlate(emps []platform.Employee, ws operate.Workspace, o CorrelateOptions) ([]types.Finding, Report) {
	now := time.Now().UTC()
	if o.Now != nil {
		now = o.Now()
	}
	n := 0
	id := func() string {
		n++
		if o.NewID != nil {
			return o.NewID()
		}
		return fmt.Sprintf("hris-%d", n)
	}
	rep := Report{Employees: len(emps), Accounts: len(ws.Users)}
	if len(emps) == 0 {
		rep.ChecksNotRun = append(rep.ChecksNotRun, "no employee records are stored, so accounts could not be checked against employment — sync your HR system first")
		return nil, rep
	}
	if len(ws.Users) == 0 {
		rep.ChecksNotRun = append(rep.ChecksNotRun, "no identity-provider accounts were available, so leavers could not be checked for standing access — connect Google Workspace, Microsoft 365 or Okta")
		return nil, rep
	}
	provider := ws.Provider
	if provider == "" {
		provider = "your identity provider"
	}

	// address → employee. Built once; a collision (two records asserting the same address) keeps
	// the first and is not a finding — the HRIS's data quality is not the account's fault.
	byEmail := map[string]int{}
	withEmail := 0
	for i, e := range emps {
		addrs := emailsOf(e)
		if len(addrs) > 0 {
			withEmail++
		}
		for _, a := range addrs {
			if _, dup := byEmail[a]; !dup {
				byEmail[a] = i
			}
		}
	}
	if withEmail == 0 {
		rep.ChecksNotRun = append(rep.ChecksNotRun, "the employee records carry no email addresses, so none could be matched to an account — check the HRIS export includes work email")
		return nil, rep
	}

	var out []types.Finding
	terminatedSeen := map[int]bool{}
	for _, u := range ws.Users {
		addr := norm(u.Email)
		if addr == "" {
			continue
		}
		ei, ok := byEmail[addr]
		if !ok {
			if !u.Suspended {
				rep.Unmatched++
				out = append(out, finding(id(), "hris::account-without-hr-record", types.SeverityLow,
					"Account has no HR record: "+u.Email, u.Email,
					fmt.Sprintf("%s is an active account in %s but matches no employee, contractor or leaver in your HR system. It may be a service account, a shared mailbox, or a person HR never recorded — confirm which and record an owner, so the next access review has someone to ask.", u.Email, provider),
					now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.2"}, ISO27001: []string{"A.5.16"}, NIST80053: []string{"AC-2"}, CISv8: []string{"5.1"}, NISTCSF: []string{"PR.AC-1"}})))
			}
			continue
		}
		rep.Matched++
		e := emps[ei]
		term, since := terminated(e, now)
		if !term {
			continue
		}
		if !terminatedSeen[ei] {
			terminatedSeen[ei] = true
			rep.Terminated++
		}
		if u.Suspended {
			rep.LeaversDeprovisioned++
			continue
		}
		rep.LeaversWithAccess++
		sev := types.SeverityHigh
		role := ""
		if u.Admin || u.SuperAdmin {
			sev = types.SeverityCritical
			role = " and holds an administrator role"
		}
		when := "is recorded as no longer employed"
		if e.EndDate != "" {
			when = "left on " + e.EndDate
			if since > 0 {
				when += fmt.Sprintf(" (%d days ago)", since)
			}
		}
		who := u.Email
		if e.Name != "" {
			who = e.Name + " (" + u.Email + ")"
		}
		out = append(out, finding(id(), "hris::leaver-with-active-account", sev,
			"Former employee still has an active account: "+u.Email, u.Email,
			fmt.Sprintf("%s %s according to your HR system, but their %s account is still enabled%s. Offboarding did not complete: suspend the account and revoke sessions, then check what else it can reach.", who, when, provider, role),
			now, comp(types.Compliance{SOC2: []string{"CC6.2", "CC6.3"}, ISO27001: []string{"A.5.18"}, NIST80053: []string{"AC-2(3)", "PS-4"},
				NIST800171: []string{"3.1.1"}, CISv8: []string{"5.3", "6.2"}, HIPAA: []string{"164.308(a)(3)(ii)(C)"}, PCI: []string{"8.2.5"},
				GDPR: []string{"Art. 32"}, SOX: []string{"ITGC: Access to Programs & Data"}, FedRAMP: []string{"AC-2"}, DPDP: []string{"Sec. 8(5)"}, NISTCSF: []string{"PR.AC-1"}})))
	}
	// Terminated employees with NO account at all are the quiet success case; count them so the
	// denominator is honest.
	for i, e := range emps {
		if terminatedSeen[i] {
			continue
		}
		if t, _ := terminated(e, now); t {
			rep.Terminated++
			rep.LeaversDeprovisioned++
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out, rep
}

// terminated reports whether the HRIS says this person has left, and how many days ago if a date
// is recorded. A status of terminated is enough on its own; otherwise a recorded end date that has
// passed decides. A future end date is a scheduled departure and is NOT a leaver.
func terminated(e platform.Employee, now time.Time) (bool, int) {
	end, hasEnd := parseDate(e.EndDate)
	if hasEnd && end.After(now) {
		return false, 0
	}
	switch {
	case e.Status == platform.EmploymentTerminated:
		if hasEnd {
			return true, int(now.Sub(end).Hours() / 24)
		}
		return true, 0
	case hasEnd:
		return true, int(now.Sub(end).Hours() / 24)
	}
	return false, 0
}

func parseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	if len(s) >= 10 {
		if t, err := time.Parse("2006-01-02", s[:10]); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func emailsOf(e platform.Employee) []string {
	var out []string
	if a := norm(e.WorkEmail); a != "" {
		out = append(out, a)
	}
	for _, p := range e.PersonalEmails {
		if a := norm(p); a != "" {
			out = append(out, a)
		}
	}
	return out
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func finding(fid, rule string, sev types.Severity, title, endpoint, desc string, now time.Time, c *types.Compliance) types.Finding {
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "hris", Severity: sev,
		Title: title, Endpoint: endpoint, Description: desc,
		Compliance: c, DiscoveredAt: now,
		// grounded by two systems of record agreeing on an address and disagreeing on status:
		VerificationStatus: types.VerificationVerified,
	}
}

func comp(c types.Compliance) *types.Compliance { return &c }

// NormalizeStatus maps a provider's employment status onto the platform vocabulary. Unknown
// values are kept as EmploymentUnknown rather than guessed: a status we do not recognise must not
// become "terminated" (a false leaver) or "active" (a hidden one).
func NormalizeStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "active", "employed", "current":
		return platform.EmploymentActive
	case "pending", "hired", "onboarding", "pre-start", "prestart":
		return platform.EmploymentPending
	case "inactive", "terminated", "separated", "offboarded", "former", "resigned":
		return platform.EmploymentTerminated
	}
	return platform.EmploymentUnknown
}
