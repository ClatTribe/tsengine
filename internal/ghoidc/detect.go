package ghoidc

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// detect.go turns trust-policy analysis into findings that flow through the ordinary
// machinery — L1.5 enrichment, unified issues, incidents, GRC, the approval desk.
// Nothing here detects anything new; it is the reachable surface for trust.go, which
// is the difference between a capability and a package nobody can call.
//
// SNAPSHOT-DRIVEN, like sspm / osint / tprm. The caller supplies what it observed; a
// clean estate yields ZERO findings. Two facts are SUPPLIED and never inferred:
//
//   - Privileged comes from real IAM data (awsfetch's RawIAMRole.Admin). trust.go
//     refuses to guess blast radius because a trust policy does not contain it — but
//     when the caller genuinely knows, an over-broad trust on an ADMIN role is a
//     materially worse fact than the same trust on a log-writer, and saying so is
//     grounded rather than speculative.
//   - ReposComplete gates the unknown-repository check. A partial repo inventory would
//     accuse a trust policy of naming a repo you own but we failed to list, so the
//     check does not run without a completeness claim — and says so in ChecksNotRun
//     rather than passing silently.

// Role is one AWS role as observed, with the trust policy verbatim.
type Role struct {
	ARN     string
	Name    string
	Account string
	// TrustPolicy is the decoded assume-role policy document JSON.
	TrustPolicy string
	// Privileged reports that this role holds administrative permissions. Supplied by
	// the caller from IAM, never inferred here.
	Privileged bool
}

// Estate is the observed GitHub↔AWS trust surface.
type Estate struct {
	Roles []Role
	// OwnedRepos are the "owner/repo" slugs the organisation actually owns.
	OwnedRepos []string
	// ReposComplete asserts OwnedRepos is the FULL list. False (the default) disables
	// the unknown-repository check rather than risking a false accusation.
	ReposComplete bool
}

// Assessment is what Assess found, and what it could not look at.
type Assessment struct {
	Findings []types.Finding
	// ChecksNotRun explains, per check, why it was skipped. Present so a caller never
	// reads "0 findings" as a clean estate when a check never ran.
	ChecksNotRun map[string]string
}

const (
	// RuleUnknownRepo fires when a trust names a repository the org does not own.
	RuleUnknownRepo = "github_oidc_trusts_unowned_repository"
)

// Assess evaluates every role's trust policy for GitHub-Actions over-trust.
//
// Grounded (§10): findings come only from statements that really grant GitHub
// web-identity assumption. A role with no GitHub trust, or a correctly pinned one,
// yields nothing. A trust policy that cannot be parsed is reported in ChecksNotRun for
// that role — never silently treated as clean.
func Assess(est Estate, now time.Time) Assessment {
	a := Assessment{ChecksNotRun: map[string]string{}}
	idn := 0
	id := func() string { idn++; return fmt.Sprintf("ghoidc-%03d", idn) }

	owned := map[string]bool{}
	for _, r := range est.OwnedRepos {
		owned[strings.ToLower(strings.TrimSpace(r))] = true
	}
	if !est.ReposComplete {
		a.ChecksNotRun[RuleUnknownRepo] = "the repository inventory is not known to be complete, so a " +
			"trust naming a repository we did not list would be accused wrongly — connect GitHub and " +
			"re-run to enable this check"
	}

	for _, role := range est.Roles {
		if strings.TrimSpace(role.TrustPolicy) == "" {
			continue // no trust policy observed: nothing to assess, and nothing claimed
		}
		an := Analyze([]byte(role.TrustPolicy))
		if !an.Parsed {
			a.ChecksNotRun["trust_policy:"+role.ARN] = "the trust policy could not be parsed — this " +
				"role was NOT assessed and must not be read as clean"
			continue
		}
		if len(an.OtherFederated) > 0 {
			// A federated identity provider we do not evaluate can assume this role. Declaring it is
			// the whole point: silently skipping made "an entire workforce IdP federates in here" and
			// "nobody federates in here" the same answer, and the second is what a reader infers from
			// an assessment that says nothing.
			a.ChecksNotRun["federated_trust:"+role.ARN] = "this role is assumable by a federated " +
				"identity provider this check does not evaluate (" +
				strings.Join(dedupeSorted(an.OtherFederated), ", ") + ") — GitHub-Actions analysis " +
				"does not apply to it and it was NOT assessed, so read it as unchecked rather than clean"
		}
		if !an.TrustsGitHub {
			continue // not reachable from GitHub Actions at all
		}

		for _, w := range an.Weaknesses {
			a.Findings = append(a.Findings, weaknessFinding(id(), role, w, now))
		}
		if est.ReposComplete {
			a.Findings = append(a.Findings, unownedRepoFindings(id, role, an, owned, now)...)
		}
	}
	return a
}

// weaknessFinding renders one trust weakness as a finding, escalating severity when the
// role is known-privileged.
// dedupeSorted keeps the declaration stable and readable when several statements name the same
// provider — a repeated ARN in the message reads like several distinct federations.
func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func weaknessFinding(fid string, role Role, w Weakness, now time.Time) types.Finding {
	sev := severity(w.Severity)
	desc := w.Detail + ". " + w.Fix + "."

	// The escalation is the whole reason Privileged is carried: "any repository in your
	// org can assume this role" and "…can assume an ADMIN role" are different facts, and
	// only the second is an account takeover. Escalate by one step, never past critical,
	// and SAY why — an unexplained severity bump is indistinguishable from a guess.
	if role.Privileged && sev != types.SeverityCritical {
		sev = escalate(sev)
		desc += " This role holds administrative permissions, so the over-broad trust is an " +
			"account-takeover path rather than a scoped one."
	}

	return types.Finding{
		ID:       fid,
		RuleID:   "ghoidc::" + w.Kind,
		Tool:     "ghoidc",
		Severity: sev,
		// CWE-1391 use of weak credential / CWE-284 improper access control: the trust
		// condition IS the access-control decision here.
		CWE:         []string{"CWE-284", "CWE-1391"},
		Endpoint:    role.ARN,
		Title:       titleFor(w.Kind, role),
		Description: desc,
		ToolArgs: map[string]string{
			"role":       role.Name,
			"account":    role.Account,
			"sid":        w.Sid,
			"observed":   w.Observed,
			"privileged": fmt.Sprintf("%t", role.Privileged),
		},
		// T1199 trusted relationship — the technique this literally is: abusing a trusted
		// third party's access rather than breaching the target directly.
		MITRETechniques: []string{"T1199", "T1078.004"},
		Compliance: &types.Compliance{
			SOC2:      []string{"CC6.1", "CC6.3"},
			CISv8:     []string{"3.3", "6.8"},
			NISTCSF:   []string{"PR.AA-05"},
			ISO27001:  []string{"A.5.15", "A.5.17"},
			NIST80053: []string{"AC-2", "AC-3", "AC-6"},
			PCI:       []string{"7.2.1"},
		},
		// A deterministic read of a real policy document, not a signature guess — but not
		// an executed exploit either. Corroborated is the honest rung.
		VerificationStatus: types.VerificationCorroborated,
		DiscoveredAt:       now,
	}
}

// unownedRepoFindings reports a trust pinned to a repository the organisation does not
// own — either a typo that silently breaks the pipeline, or a deliberate trust of a
// third party's repository, and both are worth a human's attention.
//
// Only exact, non-wildcarded subject pins are checked: a wildcard is already reported by
// its own weakness, and re-reporting it here would double-count one defect.
func unownedRepoFindings(id func() string, role Role, an Analysis, owned map[string]bool, now time.Time) []types.Finding {
	var out []types.Finding
	seen := map[string]bool{}
	for _, st := range an.Statements {
		for _, c := range st.Subjects {
			if c.Wildcard() {
				continue
			}
			repo := RepositoryOfSubject(c.Value)
			if repo == "" || seen[repo] || owned[strings.ToLower(repo)] {
				continue
			}
			seen[repo] = true
			out = append(out, types.Finding{
				ID: id(), RuleID: "ghoidc::" + RuleUnknownRepo, Tool: "ghoidc",
				Severity: types.SeverityMedium,
				CWE:      []string{"CWE-284"},
				Endpoint: role.ARN,
				Title:    "AWS role " + role.Name + " trusts a GitHub repository the organisation does not own",
				Description: "The trust policy pins `sub` to " + c.Value + ", whose repository " + repo +
					" is not in the connected organisation's repository list. Either the slug is wrong — in " +
					"which case the pipeline this role exists for cannot authenticate — or a third party's " +
					"repository is genuinely trusted with this role, which should be a deliberate decision.",
				ToolArgs: map[string]string{
					"role": role.Name, "account": role.Account,
					"repository": repo, "observed": c.Op + " " + c.Value,
				},
				MITRETechniques: []string{"T1199"},
				Compliance: &types.Compliance{
					SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"},
					NIST80053: []string{"AC-2", "AC-3"}, ISO27001: []string{"A.5.15"},
				},
				VerificationStatus: types.VerificationCorroborated,
				DiscoveredAt:       now,
			})
		}
	}
	return out
}

// RepositoryOfSubject pulls "owner/repo" out of a GitHub subject, or "" when the pattern is
// not the repo: form we can read.
func RepositoryOfSubject(sub string) string {
	if !strings.HasPrefix(sub, "repo:") {
		return ""
	}
	rest := strings.TrimPrefix(sub, "repo:")
	owner, after, ok := strings.Cut(rest, "/")
	if !ok || owner == "" {
		return ""
	}
	repo, _, _ := strings.Cut(after, ":")
	if repo == "" {
		return ""
	}
	return owner + "/" + repo
}

func titleFor(kind string, role Role) string {
	switch kind {
	case SubjectUnconstrained:
		return "Any GitHub repository can assume AWS role " + role.Name
	case SubjectSpansRepositories:
		return "AWS role " + role.Name + " trusts GitHub repositories by wildcard"
	case SubjectSpansRefs:
		return "AWS role " + role.Name + " can be assumed from any branch or environment"
	case AudienceUnconstrained:
		return "AWS role " + role.Name + " accepts a GitHub OIDC token minted for any audience"
	}
	return "GitHub OIDC trust weakness on AWS role " + role.Name
}

func severity(s string) types.Severity {
	switch s {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	}
	return types.SeverityLow
}

func escalate(s types.Severity) types.Severity {
	switch s {
	case types.SeverityHigh:
		return types.SeverityCritical
	case types.SeverityMedium:
		return types.SeverityHigh
	case types.SeverityLow:
		return types.SeverityMedium
	}
	return s
}
