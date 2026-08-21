package gcpwif

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

var at = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

const poolPrefix = "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/gh"

func prov(cond string) Provider {
	return Provider{
		ProjectNumber: "123", PoolID: "gh", ID: "github",
		IssuerURI:          GitHubIssuerURI,
		AllowedAudiences:   []string{"//iam.googleapis.com/projects/123"},
		AttributeCondition: cond,
	}
}

func sa(email string, priv bool, members ...string) ServiceAccount {
	return ServiceAccount{Email: email, Privileged: priv,
		Bindings: []Binding{{Role: "roles/iam.workloadIdentityUser", Members: members}}}
}

func rules(a Assessment) map[string]types.Severity {
	m := map[string]types.Severity{}
	for _, f := range a.Findings {
		m[f.RuleID] = f.Severity
	}
	return m
}

func TestParseMember_ScopeLadder(t *testing.T) {
	for _, tc := range []struct {
		in    string
		scope PrincipalScope
		repo  string
	}{
		{poolPrefix + "/*", ScopeEntirePool, ""},
		{poolPrefix, ScopeEntirePool, ""},
		{poolPrefix + "/attribute.repository/acme/api", ScopeAttributeGroup, "acme/api"},
		{poolPrefix + "/attribute.repository_owner/acme", ScopeAttributeGroup, ""},
		{"principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/gh/subject/repo:acme/api:ref:refs/heads/main", ScopeExactSubject, "acme/api"},
		{"serviceAccount:x@y.iam.gserviceaccount.com", ScopeNotFederated, ""},
		{"user:a@b.com", ScopeNotFederated, ""},
	} {
		m := ParseMember(tc.in)
		if m.Scope != tc.scope {
			t.Errorf("%s: scope = %v, want %v", tc.in, m.Scope, tc.scope)
		}
		if got := m.RepositoryOf(); got != tc.repo {
			t.Errorf("%s: repo = %q, want %q", tc.in, got, tc.repo)
		}
	}
}

// An unrecognised selector must be treated as the WIDE case, not the narrow one:
// guessing narrow is the dangerous direction.
func TestParseMember_UnknownSelectorIsTreatedAsWholePoolNotNarrow(t *testing.T) {
	m := ParseMember(poolPrefix + "/somethingNewGoogleAdded/xyz")
	if m.Scope != ScopeEntirePool {
		t.Fatal("an unrecognised selector must not be assumed narrow — that errs toward silence")
	}
}

// THE JOIN. Neither object is remarkable alone; together they are open impersonation.
func TestAssess_UnconditionedProviderPlusPoolWideBindingIsTheJoinFinding(t *testing.T) {
	a := Assess(Estate{
		Providers:       []Provider{prov("")},
		ServiceAccounts: []ServiceAccount{sa("deploy@p.iam.gserviceaccount.com", false, poolPrefix+"/*")},
	}, at)

	r := rules(a)
	if r["gcpwif::"+RuleUnconditionedPoolWideImpersonation] != types.SeverityCritical {
		t.Fatalf("an unconditioned provider governing a pool-wide binding is open impersonation; got %v", r)
	}
	// Double-counting one defect as two findings inflates the estate.
	if _, both := r["gcpwif::"+RuleBindingEntirePool]; both {
		t.Fatal("the join supersedes the pool-wide binding finding — reporting both counts one defect twice")
	}
}

// Each half ALONE must produce its own, lesser finding — and must NOT produce the join.
func TestAssess_EachHalfAloneIsNotTheJoin(t *testing.T) {
	// Conditioned provider + pool-wide binding: the binding is loose, but not open.
	loose := Assess(Estate{
		Providers:       []Provider{prov("assertion.repository_owner=='acme'")},
		ServiceAccounts: []ServiceAccount{sa("d@p.iam.gserviceaccount.com", false, poolPrefix+"/*")},
	}, at)
	r := rules(loose)
	if _, joined := r["gcpwif::"+RuleUnconditionedPoolWideImpersonation]; joined {
		t.Fatal("a conditioned provider is not open to the internet — the join must not fire")
	}
	if r["gcpwif::"+RuleBindingEntirePool] != types.SeverityHigh {
		t.Fatalf("the pool-wide binding is still its own finding; got %v", r)
	}

	// Unconditioned provider + narrowly scoped binding: the provider is its own finding.
	narrow := Assess(Estate{
		Providers: []Provider{prov("")},
		ServiceAccounts: []ServiceAccount{
			sa("d@p.iam.gserviceaccount.com", false, poolPrefix+"/attribute.repository/acme/api")},
	}, at)
	r2 := rules(narrow)
	if r2["gcpwif::"+RuleProviderUnconditioned] != types.SeverityHigh {
		t.Fatalf("an unconditioned provider is reported on its own; got %v", r2)
	}
	if _, joined := r2["gcpwif::"+RuleUnconditionedPoolWideImpersonation]; joined {
		t.Fatal("a narrow binding is not open impersonation")
	}
}

func TestAssess_PrivilegedServiceAccountEscalatesAndSaysWhy(t *testing.T) {
	a := Assess(Estate{
		Providers:       []Provider{prov("assertion.repository=='acme/api'")},
		ServiceAccounts: []ServiceAccount{sa("admin@p.iam.gserviceaccount.com", true, poolPrefix+"/*")},
	}, at)
	for _, f := range a.Findings {
		if f.RuleID == "gcpwif::"+RuleBindingEntirePool && f.Severity != types.SeverityCritical {
			t.Fatalf("a pool-wide binding on a PRIVILEGED account is critical, got %s", f.Severity)
		}
	}
}

func TestAssess_TightFederationYieldsNothing(t *testing.T) {
	a := Assess(Estate{
		Providers: []Provider{prov("assertion.repository=='acme/api'")},
		ServiceAccounts: []ServiceAccount{
			sa("d@p.iam.gserviceaccount.com", false, poolPrefix+"/attribute.repository/acme/api")},
		OwnedRepos: []string{"acme/api"}, ReposComplete: true,
	}, at)
	if len(a.Findings) != 0 {
		t.Fatalf("a correctly scoped federation must yield ZERO findings, got %+v", a.Findings)
	}
}

// Grounding: not our claim to make.
func TestAssess_IgnoresNonGitHubAndNonImpersonation(t *testing.T) {
	// A pool that federates something else entirely.
	other := Assess(Estate{
		Providers:       []Provider{{ProjectNumber: "123", PoolID: "gh", ID: "gl", IssuerURI: "https://gitlab.com", AllowedAudiences: []string{"a"}}},
		ServiceAccounts: []ServiceAccount{sa("d@p.iam.gserviceaccount.com", false, poolPrefix+"/*")},
	}, at)
	if len(other.Findings) != 0 {
		t.Fatalf("a non-GitHub provider is not this package's finding, got %+v", other.Findings)
	}

	// A non-impersonation role granted to the whole pool: real, but not act-as.
	viewer := Estate{
		Providers: []Provider{prov("")},
		ServiceAccounts: []ServiceAccount{{Email: "d@p.iam.gserviceaccount.com",
			Bindings: []Binding{{Role: "roles/viewer", Members: []string{poolPrefix + "/*"}}}}},
	}
	a := Assess(viewer, at)
	for _, f := range a.Findings {
		if f.RuleID == "gcpwif::"+RuleUnconditionedPoolWideImpersonation {
			t.Fatal("roles/viewer does not let anyone act as the service account")
		}
	}
}

// A binding on a pool that has no GitHub provider must not be attributed to GitHub.
func TestAssess_BindingOnAnUngovernedPoolIsNotClaimed(t *testing.T) {
	a := Assess(Estate{
		Providers: []Provider{prov("")}, // pool "gh"
		ServiceAccounts: []ServiceAccount{sa("d@p.iam.gserviceaccount.com", false,
			"principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/OTHER/*")},
	}, at)
	for _, f := range a.Findings {
		if f.RuleID == "gcpwif::"+RuleUnconditionedPoolWideImpersonation {
			t.Fatal("a binding on a different pool must not inherit this pool's provider weakness")
		}
	}
}

func TestAssess_UnownedRepoCheckIsGatedOnCompleteness(t *testing.T) {
	est := Estate{
		Providers: []Provider{prov("assertion.repository=='acme/api'")},
		ServiceAccounts: []ServiceAccount{
			sa("d@p.iam.gserviceaccount.com", false, poolPrefix+"/attribute.repository/stranger/repo")},
		OwnedRepos: []string{"acme/api"},
	}
	a := Assess(est, at)
	if _, said := a.ChecksNotRun[RuleUnownedRepo]; !said {
		t.Fatal("a skipped check must declare itself, or 0 findings reads as clean")
	}
	for _, f := range a.Findings {
		if f.RuleID == "gcpwif::"+RuleUnownedRepo {
			t.Fatal("without a complete inventory we must not accuse a binding")
		}
	}

	est.ReposComplete = true
	b := Assess(est, at)
	var found bool
	for _, f := range b.Findings {
		if f.RuleID == "gcpwif::"+RuleUnownedRepo {
			found = true
			if f.ToolArgs["repository"] != "stranger/repo" {
				t.Fatalf("the finding must name the repository it read, got %q", f.ToolArgs["repository"])
			}
		}
	}
	if !found {
		t.Fatal("with a complete inventory, a binding on an unlisted repo is a real finding")
	}
}

// We can prove ABSENCE of a condition. We must never claim a present one is adequate.
func TestAssess_PresentConditionIsNotAssertedAdequate(t *testing.T) {
	// A condition that mentions nothing useful is still PRESENT — we do not interpret CEL,
	// so we must not report it as unconditioned.
	a := Assess(Estate{
		Providers:       []Provider{prov("true")},
		ServiceAccounts: []ServiceAccount{sa("d@p.iam.gserviceaccount.com", false, poolPrefix+"/*")},
	}, at)
	if _, unconditioned := rules(a)["gcpwif::"+RuleProviderUnconditioned]; unconditioned {
		t.Fatal("a condition IS present; calling it absent would be a claim we cannot support " +
			"without interpreting CEL")
	}
	p := prov("assertion.repository=='acme/api'")
	if !p.ConditionMentions("repository") || p.ConditionMentions("environment") {
		t.Fatal("ConditionMentions is lexical and must answer only what it can see")
	}
}
