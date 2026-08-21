package gcpwif

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Rule ids. Each names one defect, because each has a different fix and a different
// owner — the provider condition is edited by whoever runs the pool, the binding by
// whoever owns the service account.
const (
	// RuleProviderUnconditioned: the pool provider has NO attribute condition, so it will
	// mint an identity for a token from ANY GitHub repository.
	RuleProviderUnconditioned = "gcp_wif_provider_unconditioned"
	// RuleBindingEntirePool: a service account grants impersonation to the whole pool.
	RuleBindingEntirePool = "gcp_wif_binding_grants_entire_pool"
	// RuleBindingOwnerWide: impersonation granted to every repository under an owner.
	RuleBindingOwnerWide = "gcp_wif_binding_grants_whole_org"
	// RuleUnconditionedPoolWideImpersonation is THE JOIN — an unconditioned provider AND a
	// pool-wide binding. Neither object is remarkable alone; together they are open
	// impersonation from the public internet.
	RuleUnconditionedPoolWideImpersonation = "gcp_wif_open_impersonation"
	// RuleAudienceUnconstrained: the provider declares no allowed audiences.
	RuleAudienceUnconstrained = "gcp_wif_audience_unconstrained"
	// RuleUnownedRepo: a binding scoped to a repository the organisation does not own.
	RuleUnownedRepo = "gcp_wif_binds_unowned_repository"
)

// Estate is the observed GCP federation surface.
type Estate struct {
	Providers       []Provider
	ServiceAccounts []ServiceAccount
	OwnedRepos      []string
	// ReposComplete asserts OwnedRepos is the full list; false disables the unowned-repo
	// check rather than risking a false accusation.
	ReposComplete bool
}

// Assessment is what Assess found and what it could not look at.
type Assessment struct {
	Findings     []types.Finding
	ChecksNotRun map[string]string
}

// Assess evaluates GCP Workload Identity Federation for GitHub over-trust.
//
// Grounded (§10): only providers that really federate the GitHub issuer, and only
// bindings whose role really grants impersonation. A tightly-scoped federation yields
// ZERO findings. Adequacy of a present attribute condition is never asserted — see the
// package header.
func Assess(est Estate, now time.Time) Assessment {
	a := Assessment{ChecksNotRun: map[string]string{}}
	n := 0
	id := func() string { n++; return fmt.Sprintf("gcpwif-%03d", n) }

	owned := map[string]bool{}
	for _, r := range est.OwnedRepos {
		owned[strings.ToLower(strings.TrimSpace(r))] = true
	}
	if !est.ReposComplete {
		a.ChecksNotRun[RuleUnownedRepo] = "the repository inventory is not known to be complete, so a " +
			"binding naming a repository we did not list would be accused wrongly — connect GitHub and re-run"
	}

	// Index the GitHub-federating providers by pool resource, so a binding can be joined
	// to the provider that governs it. A binding on a pool with no GitHub provider is a
	// different product's problem.
	github := map[string][]Provider{}
	for _, p := range est.Providers {
		if !p.FederatesGitHub() {
			continue
		}
		github[p.PoolResource()] = append(github[p.PoolResource()], p)
		a.Findings = append(a.Findings, providerFindings(id, p, now)...)
	}
	if len(github) == 0 {
		return a // nothing federates GitHub; the bindings below cannot mean what we'd claim
	}

	for _, sa := range est.ServiceAccounts {
		for _, b := range sa.Bindings {
			if !b.Impersonates() {
				continue // a non-impersonation role on a pool principal is not this finding
			}
			for _, raw := range b.Members {
				m := ParseMember(raw)
				if m.Scope == ScopeNotFederated {
					continue
				}
				provs, governs := github[m.Pool]
				if !governs {
					continue // this pool has no GitHub provider — not our claim to make
				}
				a.Findings = append(a.Findings, bindingFindings(id, sa, b, m, provs, owned, est.ReposComplete, now)...)
			}
		}
	}
	return a
}

func providerFindings(id func() string, p Provider, now time.Time) []types.Finding {
	var out []types.Finding
	name := p.PoolID + "/" + p.ID

	if p.AttributeCondition == "" {
		out = append(out, wifFinding(id(), RuleProviderUnconditioned, types.SeverityHigh,
			"GCP workload identity provider "+name+" accepts tokens from any GitHub repository",
			p.PoolResource()+"/providers/"+p.ID,
			"This provider federates GitHub Actions with no attribute condition, so it will mint a "+
				"workload identity for a token from ANY repository on GitHub — not only yours. Whether that "+
				"identity can do anything depends on the service-account bindings, which is why this is "+
				"reported separately from them.",
			"Set an attribute condition on the provider, e.g. "+
				"assertion.repository_owner == 'YOUR_ORG' && assertion.repository == 'YOUR_ORG/YOUR_REPO'.",
			map[string]string{"pool": p.PoolID, "provider": p.ID, "issuer": p.IssuerURI},
			now))
	}
	if len(p.AllowedAudiences) == 0 {
		out = append(out, wifFinding(id(), RuleAudienceUnconstrained, types.SeverityMedium,
			"GCP workload identity provider "+name+" declares no allowed audiences",
			p.PoolResource()+"/providers/"+p.ID,
			"No allowed audiences are configured, so a token minted for a different relying party is accepted.",
			"Set allowedAudiences on the provider to the audience your workflow requests.",
			map[string]string{"pool": p.PoolID, "provider": p.ID},
			now))
	}
	return out
}

func bindingFindings(id func() string, sa ServiceAccount, b Binding, m Member,
	provs []Provider, owned map[string]bool, reposComplete bool, now time.Time) []types.Finding {

	var out []types.Finding
	args := map[string]string{
		"service_account": sa.Email, "role": b.Role, "member": m.Raw,
		"privileged": fmt.Sprintf("%t", sa.Privileged),
	}

	switch m.Scope {
	case ScopeEntirePool:
		// THE JOIN. An unconditioned provider governing a pool-wide binding is open
		// impersonation from the public internet — a fact neither object states alone,
		// which is the whole reason this package reads them together.
		if openProvider := firstUnconditioned(provs); openProvider != nil {
			sev := types.SeverityCritical
			desc := "Service account " + sa.Email + " grants " + b.Role + " to EVERY identity in " +
				"workload identity pool " + openProvider.PoolID + ", and that pool's provider " +
				openProvider.ID + " has no attribute condition. The two are individually unremarkable and " +
				"together mean any GitHub Actions workflow, in any repository on the internet, can " +
				"impersonate this service account. Neither the binding nor the provider says this on its own."
			if sa.Privileged {
				desc += " This service account holds administrative permissions, so the path is a project takeover."
			}
			out = append(out, wifFinding(id(), RuleUnconditionedPoolWideImpersonation, sev,
				"Any GitHub repository can impersonate GCP service account "+sa.Email,
				"//iam.googleapis.com/"+sa.Email, desc,
				"Narrow BOTH halves: scope the binding to principalSet://…/attribute.repository/OWNER/REPO, "+
					"and set an attribute condition on provider "+openProvider.ID+".",
				args, now))
			break // the join supersedes the pool-wide finding; reporting both double-counts one defect
		}
		sev := types.SeverityHigh
		if sa.Privileged {
			sev = types.SeverityCritical
		}
		out = append(out, wifFinding(id(), RuleBindingEntirePool, sev,
			"GCP service account "+sa.Email+" is impersonable by an entire workload identity pool",
			"//iam.googleapis.com/"+sa.Email,
			"The binding grants "+b.Role+" to every identity the pool can mint, including identities "+
				"nobody has created yet. The pool's provider does constrain which tokens it accepts, so this "+
				"is not open to the internet — but the binding places no limit of its own.",
			"Scope the member to principalSet://…/attribute.repository/OWNER/REPO.",
			args, now))

	case ScopeAttributeGroup:
		if m.Attribute == "repository_owner" {
			sev := types.SeverityHigh
			if !sa.Privileged {
				sev = types.SeverityMedium
			}
			out = append(out, wifFinding(id(), RuleBindingOwnerWide, sev,
				"GCP service account "+sa.Email+" is impersonable by every repository in "+m.Value,
				"//iam.googleapis.com/"+sa.Email,
				"The binding is scoped to repository_owner '"+m.Value+"', so every repository in that "+
					"organisation — including one any member can create — can impersonate this service account.",
				"Scope to the specific repository: principalSet://…/attribute.repository/"+m.Value+"/REPO.",
				args, now))
		}
	}

	// A binding pinned to a repository the org does not own: a typo that silently breaks
	// the pipeline, or a third party genuinely trusted. Only exact repo scopes, and only
	// with a complete inventory.
	if reposComplete {
		if repo := m.RepositoryOf(); repo != "" && !owned[strings.ToLower(repo)] {
			ra := map[string]string{"service_account": sa.Email, "repository": repo, "member": m.Raw}
			out = append(out, wifFinding(id(), RuleUnownedRepo, types.SeverityMedium,
				"GCP service account "+sa.Email+" trusts a GitHub repository the organisation does not own",
				"//iam.googleapis.com/"+sa.Email,
				"The binding is scoped to repository "+repo+", which is not in the connected organisation's "+
					"repository list. Either the slug is wrong — in which case the pipeline cannot authenticate "+
					"— or a third party's repository is genuinely trusted, which should be deliberate.",
				"Confirm the repository is intended; correct the slug or remove the binding.",
				ra, now))
		}
	}
	return out
}

func firstUnconditioned(ps []Provider) *Provider {
	for i := range ps {
		if ps[i].AttributeCondition == "" {
			return &ps[i]
		}
	}
	return nil
}

func wifFinding(fid, rule string, sev types.Severity, title, endpoint, desc, fix string,
	args map[string]string, now time.Time) types.Finding {
	return types.Finding{
		ID: fid, RuleID: "gcpwif::" + rule, Tool: "gcpwif", Severity: sev,
		CWE:      []string{"CWE-284", "CWE-1391"},
		Endpoint: endpoint, Title: title,
		Description: desc + " " + fix,
		ToolArgs:    args,
		// T1199 trusted relationship: abusing a trusted third party's access rather than
		// breaching the target directly.
		MITRETechniques: []string{"T1199", "T1078.004"},
		Compliance: &types.Compliance{
			SOC2:      []string{"CC6.1", "CC6.3"},
			CISv8:     []string{"3.3", "6.8"},
			NISTCSF:   []string{"PR.AA-05"},
			ISO27001:  []string{"A.5.15", "A.5.17"},
			NIST80053: []string{"AC-2", "AC-3", "AC-6"},
			PCI:       []string{"7.2.1"},
		},
		VerificationStatus: types.VerificationCorroborated,
		DiscoveredAt:       now,
	}
}
