package ghoidc

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

var t0 = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func role(name string, priv bool, cond string) Role {
	return Role{
		ARN: "arn:aws:iam::123456789012:role/" + name, Name: name, Account: "123456789012",
		Privileged: priv, TrustPolicy: string(trust(cond)),
	}
}

const pinnedCond = `,"Condition":{"StringEquals":{
   "token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
   "token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`

const openCond = `,"Condition":{"StringEquals":{
   "token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}`

const orgWideCond = `,"Condition":{
   "StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
   "StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}`

func TestAssess_CorrectlyPinnedEstateYieldsNothing(t *testing.T) {
	a := Assess(Estate{Roles: []Role{role("deploy", false, pinnedCond)}}, t0)
	if len(a.Findings) != 0 {
		t.Fatalf("a correctly pinned trust must produce ZERO findings, got %+v", a.Findings)
	}
}

func TestAssess_RoleWithNoGitHubTrustIsIgnored(t *testing.T) {
	plain := Role{ARN: "arn:aws:iam::1:role/x", Name: "x",
		TrustPolicy: `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::1:root"}}]}`}
	a := Assess(Estate{Roles: []Role{plain}}, t0)
	if len(a.Findings) != 0 {
		t.Fatalf("a role not reachable from Actions is not our finding, got %+v", a.Findings)
	}
}

// The escalation that justifies carrying Privileged at all.
func TestAssess_PrivilegedRoleEscalatesSeverityAndSaysWhy(t *testing.T) {
	plain := Assess(Estate{Roles: []Role{role("logs", false, orgWideCond)}}, t0)
	priv := Assess(Estate{Roles: []Role{role("admin", true, orgWideCond)}}, t0)

	find := func(fs []types.Finding, kind string) *types.Finding {
		for i := range fs {
			if fs[i].RuleID == "ghoidc::"+kind {
				return &fs[i]
			}
		}
		return nil
	}
	lo, hi := find(plain.Findings, SubjectSpansRepositories), find(priv.Findings, SubjectSpansRepositories)
	if lo == nil || hi == nil {
		t.Fatal("both estates should report the org-wide wildcard")
	}
	if lo.Severity != types.SeverityHigh {
		t.Fatalf("org-wide trust on an ordinary role is high, got %s", lo.Severity)
	}
	if hi.Severity != types.SeverityCritical {
		t.Fatalf("org-wide trust on an ADMIN role is account takeover — want critical, got %s", hi.Severity)
	}
	if !contains(hi.Description, "administrative permissions") {
		t.Fatal("an unexplained severity bump is indistinguishable from a guess — it must say why")
	}
}

// "We could not look" must be reported, never silently clean.
func TestAssess_UnparseableTrustPolicyIsReportedNotSkippedSilently(t *testing.T) {
	bad := Role{ARN: "arn:aws:iam::1:role/x", Name: "x", TrustPolicy: "<<<broken"}
	a := Assess(Estate{Roles: []Role{bad}}, t0)
	if len(a.Findings) != 0 {
		t.Fatal("an unreadable policy must not manufacture findings")
	}
	if _, said := a.ChecksNotRun["trust_policy:arn:aws:iam::1:role/x"]; !said {
		t.Fatal("a role we could not assess must appear in ChecksNotRun, or 0 findings reads as clean")
	}
}

// The completeness gate: without a complete repo inventory the check must NOT run,
// and must say so.
func TestAssess_UnownedRepoCheckIsGatedOnInventoryCompleteness(t *testing.T) {
	est := Estate{Roles: []Role{role("deploy", false, pinnedCond)}, OwnedRepos: []string{"acme/other"}}
	a := Assess(est, t0)
	for _, f := range a.Findings {
		if f.RuleID == "ghoidc::"+RuleUnknownRepo {
			t.Fatal("without ReposComplete we must not accuse a trust of naming an unowned repo")
		}
	}
	if _, said := a.ChecksNotRun[RuleUnknownRepo]; !said {
		t.Fatal("a skipped check must be declared, not silently omitted")
	}

	est.ReposComplete = true
	b := Assess(est, t0)
	var found bool
	for _, f := range b.Findings {
		if f.RuleID == "ghoidc::"+RuleUnknownRepo {
			found = true
			if f.ToolArgs["repository"] != "acme/api" {
				t.Fatalf("the finding must name the repository read from the subject, got %q", f.ToolArgs["repository"])
			}
		}
	}
	if !found {
		t.Fatal("with a complete inventory, a trust on an unlisted repo is a real finding")
	}
	if _, said := b.ChecksNotRun[RuleUnknownRepo]; said {
		t.Fatal("a check that ran must not also be listed as not-run")
	}
}

func TestAssess_OwnedRepoIsNotAccused(t *testing.T) {
	a := Assess(Estate{
		Roles:      []Role{role("deploy", false, pinnedCond)},
		OwnedRepos: []string{"ACME/API"}, ReposComplete: true, // case-insensitive
	}, t0)
	for _, f := range a.Findings {
		if f.RuleID == "ghoidc::"+RuleUnknownRepo {
			t.Fatal("a repository the org owns must not be reported, and the match is case-insensitive")
		}
	}
}

// A wildcard subject already has its own finding; re-reporting it as an unowned repo
// would double-count one defect.
func TestAssess_WildcardSubjectIsNotAlsoReportedAsUnownedRepo(t *testing.T) {
	a := Assess(Estate{
		Roles: []Role{role("deploy", false, orgWideCond)}, OwnedRepos: nil, ReposComplete: true,
	}, t0)
	for _, f := range a.Findings {
		if f.RuleID == "ghoidc::"+RuleUnknownRepo {
			t.Fatal("a wildcard is reported by its own weakness; counting it twice inflates the estate")
		}
	}
}

func TestAssess_FindingsCarryGroundingMetadata(t *testing.T) {
	a := Assess(Estate{Roles: []Role{role("deploy", true, openCond)}}, t0)
	if len(a.Findings) == 0 {
		t.Fatal("an unconstrained trust must be reported")
	}
	f := a.Findings[0]
	if f.Endpoint == "" || f.Tool != "ghoidc" {
		t.Fatal("a finding must name the role it is about and the tool that found it")
	}
	if f.Compliance == nil || len(f.Compliance.SOC2) == 0 {
		t.Fatal("access-control trust weaknesses have a real control nexus and must carry it")
	}
	if len(f.MITRETechniques) == 0 {
		t.Fatal("trusted-relationship abuse is T1199 — the attribution belongs on the finding")
	}
	if f.VerificationStatus != types.VerificationCorroborated {
		t.Fatalf("a deterministic policy read is corroborated, not verified (nothing was exploited); got %q",
			f.VerificationStatus)
	}
	if f.DiscoveredAt != t0 {
		t.Fatal("the clock must be injected, not read from the wall")
	}
}

func TestAssess_EmptyEstateIsCleanAndSaysNothingWasSkipped(t *testing.T) {
	a := Assess(Estate{ReposComplete: true}, t0)
	if len(a.Findings) != 0 || len(a.ChecksNotRun) != 0 {
		t.Fatalf("an empty estate is vacuously clean, got %+v / %+v", a.Findings, a.ChecksNotRun)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
