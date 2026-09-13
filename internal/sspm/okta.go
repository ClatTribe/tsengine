package sspm

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Okta CONFIGURATION posture — the org's policies, not its accounts.
//
// internal/operate already reads Okta's ACCOUNTS (who lacks MFA, who is a super admin, who is
// stale, which OAuth grants are broad). What it could not say is how the org is CONFIGURED: whether
// the sign-on policy actually demands a factor, how weak the password policy is, whether MFA
// enrollment is merely optional, how long a session lives, which API tokens sit unused, whether
// ThreatInsight blocks known-bad IPs. That is the Okta half of what CISA SCuBA covers for M365 and
// Google, and it was absent — the 0.993 SCuBA number is M365/Google baseline coverage, not Okta.
//
// Every setting is a POINTER or a list read from the org: a check fires only on a value the org
// reported, and an unread endpoint (a token without okta.policies.read, an org on a plan without
// ThreatInsight) declines rather than reads as "secure" — the same isFalse/isTrue discipline the
// other providers use. The fetcher NAMES what it could not read in OktaOrg.Unread.

type OktaOrg struct {
	Name          string                `json:"name"`
	SignOnRules   []OktaSignOnRule      `json:"sign_on_rules"`
	Passwords     []OktaPasswordPolicy  `json:"password_policies"`
	MFAEnroll     []OktaMFAEnrollPolicy `json:"mfa_enroll_policies"`
	APITokens     []OktaAPIToken        `json:"api_tokens"`
	ThreatInsight *string               `json:"threat_insight,omitempty"` // "none" | "audit" | "block"; nil = unread
	NetworkZones  *int                  `json:"network_zones,omitempty"`  // count of configured zones; nil = unread
	Unread        map[string]string     `json:"unread,omitempty"`         // endpoint → why it could not be read
}

// OktaSignOnRule is one rule of an Okta sign-on policy (OKTA_SIGN_ON) — the decision of whether
// a factor is demanded lives on the RULE, not the policy.
type OktaSignOnRule struct {
	Policy         string `json:"policy"`
	Rule           string `json:"rule"`
	Status         string `json:"status"` // ACTIVE | INACTIVE
	Access         string `json:"access"` // ALLOW | DENY
	RequireFactor  *bool  `json:"require_factor,omitempty"`
	SessionMinutes *int   `json:"session_minutes,omitempty"` // maxSessionLifetimeMinutes; 0 = unlimited
	PersistCookie  *bool  `json:"persist_cookie,omitempty"`
	NetworkScope   string `json:"network_scope,omitempty"` // ANYWHERE | ZONE | ON_NETWORK | OFF_NETWORK
}

type OktaPasswordPolicy struct {
	Policy      string `json:"policy"`
	Status      string `json:"status"`
	MinLength   *int   `json:"min_length,omitempty"`
	Complexity  *int   `json:"complexity,omitempty"`   // number of character classes required (of 4)
	LockoutMax  *int   `json:"lockout_max,omitempty"`  // maxAttempts; 0 = lockout disabled
	CommonCheck *bool  `json:"common_check,omitempty"` // excludeCommonPasswords / dictionary
}

type OktaMFAEnrollPolicy struct {
	Policy   string `json:"policy"`
	Status   string `json:"status"`
	Required int    `json:"required"` // factors with enroll REQUIRED
	Optional int    `json:"optional"`
}

type OktaAPIToken struct {
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"` // zero = never, or unread
	Client   string    `json:"client,omitempty"`   // the user/app the token belongs to
}

// AssessOkta evaluates the org's configuration. A hardened org yields zero findings.
func AssessOkta(org OktaOrg, opts Options) []types.Finding {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	n := 0
	id := func() string { n++; return fmt.Sprintf("sspm-okta-%03d", n) }
	target := "okta:" + org.Name

	var f []types.Finding
	f = append(f, oktaCheckSignOnFactor(org, target, now, id)...)
	f = append(f, oktaCheckSessions(org, target, now, id)...)
	f = append(f, oktaCheckPasswordPolicy(org, target, now, id)...)
	f = append(f, oktaCheckMFAEnroll(org, target, now, id)...)
	f = append(f, oktaCheckAPITokens(org, target, now, id)...)
	f = append(f, oktaCheckThreatInsight(org, target, now, id)...)
	return f
}

// An ACTIVE, ALLOW sign-on rule that does not require a factor is a password-only door. Reported per
// rule, because the realistic failure is one legacy rule left beside a correct one.
func oktaCheckSignOnFactor(org OktaOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, r := range org.SignOnRules {
		if !strings.EqualFold(r.Status, "ACTIVE") || !strings.EqualFold(r.Access, "ALLOW") || !isFalse(r.RequireFactor) {
			continue
		}
		out = append(out, finding(id(), "sspm::okta::sign-on-rule-without-mfa", types.SeverityHigh,
			"Okta sign-on rule allows access without a second factor: "+r.Policy+" / "+r.Rule, target,
			"Rule "+r.Rule+" of sign-on policy "+r.Policy+" is ACTIVE, grants ALLOW, and does not require a factor (scope "+
				nz(r.NetworkScope, "ANYWHERE")+"). Every account this rule matches signs in with a password alone.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}, ISO27001: []string{"A.5.17"}})))
	}
	return out
}

// A session that never expires, or persists across browser restarts, is a stolen cookie that never
// expires either.
func oktaCheckSessions(org OktaOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, r := range org.SignOnRules {
		if !strings.EqualFold(r.Status, "ACTIVE") || !strings.EqualFold(r.Access, "ALLOW") {
			continue
		}
		if r.SessionMinutes != nil && (*r.SessionMinutes == 0 || *r.SessionMinutes > 7*24*60) {
			life := "unlimited"
			if *r.SessionMinutes > 0 {
				life = fmt.Sprintf("%d hours", *r.SessionMinutes/60)
			}
			out = append(out, finding(id(), "sspm::okta::session-lifetime-excessive", types.SeverityMedium,
				"Okta session lifetime is "+life+": "+r.Policy+" / "+r.Rule, target,
				"Rule "+r.Rule+" of "+r.Policy+" sets maxSessionLifetimeMinutes to "+life+"; a captured session token stays valid that long.",
				now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"4.3"}, NISTCSF: []string{"PR.AA-03"}})))
		}
		if isTrue(r.PersistCookie) {
			out = append(out, finding(id(), "sspm::okta::persistent-session-cookie", types.SeverityLow,
				"Okta sessions persist across browser restarts: "+r.Policy+" / "+r.Rule, target,
				"Rule "+r.Rule+" of "+r.Policy+" enables the persistent session cookie, so closing the browser does not end the session.",
				now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"4.3"}})))
		}
	}
	return out
}

func oktaCheckPasswordPolicy(org OktaOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, p := range org.Passwords {
		if !strings.EqualFold(p.Status, "ACTIVE") {
			continue
		}
		if p.MinLength != nil && *p.MinLength < 12 {
			out = append(out, finding(id(), "sspm::okta::password-min-length-short", types.SeverityMedium,
				fmt.Sprintf("Okta password policy %s allows %d-character passwords", p.Policy, *p.MinLength), target,
				fmt.Sprintf("Password policy %s sets minLength %d; NIST SP 800-63B and CIS recommend at least 12 for a password that is not the only factor, and longer where it is.", p.Policy, *p.MinLength),
				now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.3.6"}, CISv8: []string{"5.2"}, NIST80053: []string{"IA-5"}})))
		}
		if p.LockoutMax != nil && *p.LockoutMax == 0 {
			out = append(out, finding(id(), "sspm::okta::password-lockout-disabled", types.SeverityMedium,
				"Okta password policy "+p.Policy+" never locks out failed sign-ins", target,
				"Password policy "+p.Policy+" sets lockout maxAttempts to 0, so a password spray is never slowed by the IdP itself.",
				now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.3.4"}, CISv8: []string{"6.3"}, NIST80053: []string{"AC-7"}})))
		}
	}
	return out
}

// An MFA enrollment policy with no REQUIRED factor lets a user finish onboarding with none.
func oktaCheckMFAEnroll(org OktaOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, p := range org.MFAEnroll {
		if !strings.EqualFold(p.Status, "ACTIVE") || p.Required > 0 {
			continue
		}
		out = append(out, finding(id(), "sspm::okta::mfa-enrollment-optional", types.SeverityHigh,
			"Okta MFA enrollment policy "+p.Policy+" requires no factor", target,
			fmt.Sprintf("Enrollment policy %s marks %d factor(s) optional and none required; a user it applies to can complete sign-up and sign in with a password alone.", p.Policy, p.Optional),
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.3"}, NISTCSF: []string{"PR.AA-01"}})))
	}
	return out
}

// API tokens are long-lived bearer credentials with the creator's permissions. One nobody has used
// in ninety days is an unwatched key.
func oktaCheckAPITokens(org OktaOrg, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, t := range org.APITokens {
		last := t.LastUsed
		if last.IsZero() {
			last = t.Created
		}
		if last.IsZero() || now.Sub(last) < 90*24*time.Hour {
			continue
		}
		out = append(out, finding(id(), "sspm::okta::api-token-stale", types.SeverityMedium,
			"Okta API token "+t.Name+" unused for "+fmt.Sprintf("%d", int(now.Sub(last).Hours()/24))+" days", target,
			"API token "+t.Name+" (owner "+nz(t.Client, "unknown")+") was last used "+last.Format("2006-01-02")+". A static token carries its creator's admin permissions and expires only when revoked.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.2"}, CISv8: []string{"5.3"}, NIST80053: []string{"AC-2(3)"}})))
	}
	return out
}

func oktaCheckThreatInsight(org OktaOrg, target string, now time.Time, id func() string) []types.Finding {
	if org.ThreatInsight == nil || strings.EqualFold(*org.ThreatInsight, "block") {
		return nil
	}
	sev, what := types.SeverityMedium, "logs but does not block"
	if strings.EqualFold(*org.ThreatInsight, "none") {
		sev, what = types.SeverityMedium, "is disabled"
	}
	return []types.Finding{finding(id(), "sspm::okta::threatinsight-not-blocking", sev,
		"Okta ThreatInsight "+what+" sign-ins from known-malicious IPs", target,
		"ThreatInsight action is \""+*org.ThreatInsight+"\". Set it to block so credential-stuffing infrastructure Okta already recognises is refused before the password is checked.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC7.2"}, CISv8: []string{"13.3"}, NISTCSF: []string{"DE.CM-01"}}))}
}

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
