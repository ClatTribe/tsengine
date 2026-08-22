package gcpwif

import (
	"strings"
	"testing"
	"time"
)

func oktaProvider() Provider {
	return Provider{
		ProjectNumber: "1234567890", PoolID: "corp-pool", ID: "okta",
		IssuerURI: "https://acme.okta.com", AllowedAudiences: []string{"api://gcp"},
	}
}

// An estate that federates entirely through a non-GitHub issuer previously returned an assessment
// with ZERO findings and no note — indistinguishable from an estate nothing federates into. That is
// the reading a customer would take as "clean", for the one surface we never looked at.
func TestAssess_DeclaresNonGitHubIssuer(t *testing.T) {
	got := Assess(Estate{Providers: []Provider{oktaProvider()}}, time.Now())

	if len(got.Findings) != 0 {
		t.Fatalf("must not judge an issuer it does not model: %+v", got.Findings)
	}
	var note string
	for k, v := range got.ChecksNotRun {
		if strings.HasPrefix(k, "wif_provider:") {
			note = v
		}
	}
	if note == "" {
		t.Fatal("a non-GitHub WIF provider was dropped silently — the estate reads clean")
	}
	if !strings.Contains(note, "acme.okta.com") {
		t.Errorf("the declaration must NAME the issuer to be actionable: %q", note)
	}
}

// The service account such a pool can impersonate is the part that matters: an impersonable SA looked
// exactly like an unreachable one.
func TestAssess_DeclaresImpersonableServiceAccount(t *testing.T) {
	p := oktaProvider()
	est := Estate{
		Providers: []Provider{p},
		ServiceAccounts: []ServiceAccount{{
			Email: "deploy@proj.iam.gserviceaccount.com",
			Bindings: []Binding{{
				Role:    "roles/iam.serviceAccountTokenCreator",
				Members: []string{"principalSet://" + p.PoolResource() + "/*"},
			}},
		}},
	}
	got := Assess(est, time.Now())
	note, ok := got.ChecksNotRun["wif_impersonation:deploy@proj.iam.gserviceaccount.com"]
	if !ok {
		t.Fatal("an SA impersonable from an unassessed pool was skipped silently")
	}
	if !strings.Contains(note, "acme.okta.com") {
		t.Errorf("the declaration must name the issuer: %q", note)
	}
}

// A genuinely empty estate must stay silent: declaring a gap where no federation exists would be
// noise, and the same overclaim pointed the other way.
func TestAssess_NoFederationDeclaresNothing(t *testing.T) {
	got := Assess(Estate{}, time.Now())
	for k := range got.ChecksNotRun {
		if strings.HasPrefix(k, "wif_provider:") || strings.HasPrefix(k, "wif_impersonation:") {
			t.Errorf("declared a federation gap on an estate with no federation: %q", k)
		}
	}
}

// GitHub providers must still be ASSESSED, not diverted into the declaration.
func TestAssess_GitHubStillAssessed(t *testing.T) {
	gh := Provider{
		ProjectNumber: "1234567890", PoolID: "ci-pool", ID: "github",
		IssuerURI: GitHubIssuerURI, // no attribute condition: the definite finding
	}
	got := Assess(Estate{Providers: []Provider{gh}}, time.Now())
	if len(got.Findings) == 0 {
		t.Fatal("an unconditioned GitHub provider must still be a finding")
	}
	for k := range got.ChecksNotRun {
		if strings.HasPrefix(k, "wif_provider:") {
			t.Errorf("a GitHub provider must be assessed, not declared unassessed: %q", k)
		}
	}
}
