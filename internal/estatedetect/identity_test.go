package estatedetect

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/estateingest"
	"github.com/ClatTribe/tsengine/pkg/types"
)

var when = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

// The sentence neither detector can say on its own: the password in the stealer log belongs to an
// admin with no second factor.
func TestExposedIdentity_JoinsStealerLogToTheAdminAccount(t *testing.T) {
	g := estateingest.FromIdentityFindings([]types.Finding{
		{ID: "f-osint", RuleID: "osint::stealer-log", Endpoint: "alice@acme.com",
			Severity: types.SeverityCritical, Title: "Stealer-log credential exposure"},
		{ID: "f-idp", RuleID: "operate::admin-without-mfa", Endpoint: "alice@acme.com",
			Severity: types.SeverityHigh, Title: "Administrator without MFA"},
	}, when)

	found := Detect(g, Options{Now: when})
	var hit *types.Finding
	for i := range found {
		if found[i].RuleID == "estate::exposed-identity-no-mfa" {
			hit = &found[i]
		}
	}
	if hit == nil {
		t.Fatalf("an admin whose password is in a stealer log produced no cross-surface finding (got %d: %v)",
			len(found), rulesOf(found))
	}
	if hit.Severity != types.SeverityCritical {
		t.Errorf("an ADMIN with an exposed credential and no second factor is not %q", hit.Severity)
	}
	// The finding must cite both halves; citing one would be a claim half-backed by evidence.
	ev := strings.Join(hit.DerivedFrom, ",")
	if !strings.Contains(ev, "f-osint") || !strings.Contains(ev, "f-idp") {
		t.Errorf("the finding cites %v — it must cite BOTH findings it is built from", hit.DerivedFrom)
	}
}

// A non-privileged account still gets the finding: a known password with no second factor is a way
// in regardless of what it reaches. It must not be reported as critical, though.
func TestExposedIdentity_OrdinaryAccountIsHighNotCritical(t *testing.T) {
	g := estateingest.FromIdentityFindings([]types.Finding{
		{ID: "f1", RuleID: "osint::breached-credential", Endpoint: "bob@acme.com"},
		{ID: "f2", RuleID: "operate::user-without-mfa", Endpoint: "bob@acme.com"},
	}, when)
	for _, f := range Detect(g, Options{Now: when}) {
		if f.RuleID == "estate::exposed-identity-no-mfa" {
			if f.Severity != types.SeverityHigh {
				t.Errorf("an ordinary account reported as %q, want high", f.Severity)
			}
			return
		}
	}
	t.Fatalf("no finding for a breached credential on an account with no second factor")
}

// HALF THE CLAIM IS NOT THE CLAIM. Each half alone is already reported by the detector that found
// it; repeating it as a cross-surface finding would manufacture drama from one surface.
func TestExposedIdentity_RefusesOnHalfTheEvidence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		findings []types.Finding
	}{
		{"exposure with no MFA finding", []types.Finding{
			{ID: "f1", RuleID: "osint::stealer-log", Endpoint: "carol@acme.com"}}},
		{"no MFA with no exposure", []types.Finding{
			{ID: "f2", RuleID: "operate::admin-without-mfa", Endpoint: "carol@acme.com"}}},
	} {
		g := estateingest.FromIdentityFindings(tc.findings, when)
		for _, f := range Detect(g, Options{Now: when}) {
			if f.RuleID == "estate::exposed-identity-no-mfa" {
				t.Errorf("[%s] claimed a cross-surface takeover from one surface's finding", tc.name)
			}
		}
	}
}

// A leaked API token in a repository is a MACHINE credential. Treating it as this person's password
// would overstate what was found — the account may be perfectly protected.
func TestExposedIdentity_LeakedTokenIsNotAPersonsPassword(t *testing.T) {
	g := estateingest.FromIdentityFindings([]types.Finding{
		{ID: "f1", RuleID: "osint::leaked-secret", Endpoint: "dave@acme.com"},
		{ID: "f2", RuleID: "operate::admin-without-mfa", Endpoint: "dave@acme.com"},
	}, when)
	for _, f := range Detect(g, Options{Now: when}) {
		if f.RuleID == "estate::exposed-identity-no-mfa" {
			t.Errorf("a leaked API token was treated as the person's own password")
		}
	}
}

func rulesOf(fs []types.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}
