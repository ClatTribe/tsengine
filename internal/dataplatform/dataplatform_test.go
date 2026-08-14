package dataplatform

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/dataclass"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func at(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func fixedNow() Options { return Options{Now: func() time.Time { return at("2026-08-14") }} }

func rules(fs []types.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func has(fs []types.Finding, rule string) *types.Finding {
	for i := range fs {
		if fs[i].RuleID == rule {
			return &fs[i]
		}
	}
	return nil
}

// THE BASELINE THAT MAKES EVERY OTHER TEST MEAN SOMETHING.
//
// A well-governed warehouse must produce NOTHING. Without this, an assessor that returned a finding for
// every grant would pass all the detection tests below and be useless in production.
func TestWellGovernedEstate_YieldsNothing(t *testing.T) {
	got := Assess(Estate{
		OrgDomains: []string{"acme.com"},
		Objects: []Object{{
			Platform: "snowflake", Name: "analytics.public.customers", Type: "table",
			Sensitive: true, DataClasses: []string{"pii"},
			Grants: []Grant{
				{Grantee: "analyst_role", GranteeType: "role", Privilege: "SELECT", LastUsed: "2026-08-13"},
				{Grantee: "ACCOUNTADMIN", GranteeType: "role", Privilege: "OWNERSHIP", LastUsed: "2026-08-01"},
				{Grantee: "etl@acme.com", GranteeType: "service_account", Privilege: "SELECT", LastUsed: "2026-08-14"},
				{Grantee: "reporting_role", GranteeType: "role", Privilege: "USAGE"}, // touches no rows
			},
		}},
	}, fixedNow())
	if len(got) != 0 {
		t.Fatalf("a properly-governed warehouse produced findings: %v", rules(got))
	}
}

// PUBLIC IS NOT ONE THING. The three scopes differ by orders of magnitude in blast radius, and
// collapsing them into one alarm would leave a responder unable to tell "the internet can read our PII"
// from "our own analysts share a role".
func TestPublicScopes_AreDistinguishedNotFlattened(t *testing.T) {
	for _, tc := range []struct {
		name, grantee, wantRule string
		wantSev                 types.Severity
	}{
		{"internet", "allUsers", "dataplatform::internet-public-grant", types.SeverityCritical},
		{"provider-wide", "allAuthenticatedUsers", "dataplatform::provider-wide-grant", types.SeverityCritical},
		{"account-wide", "PUBLIC", "dataplatform::account-wide-grant", types.SeverityHigh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess(Estate{Objects: []Object{{
				Platform: "bigquery", Name: "proj.analytics.customers", Type: "table", Sensitive: true,
				Grants: []Grant{{Grantee: tc.grantee, Privilege: "SELECT"}},
			}}}, fixedNow())
			f := has(got, tc.wantRule)
			if f == nil {
				t.Fatalf("grantee %q did not produce %s; got %v", tc.grantee, tc.wantRule, rules(got))
			}
			if f.Severity != tc.wantSev {
				t.Errorf("severity = %s, want %s — the scopes must not be flattened to one level",
					f.Severity, tc.wantSev)
			}
		})
	}
}

// Account-wide on DECLARED regulated data outranks account-wide on ordinary data. Both are real; only
// one carries regulatory weight, and a queue that ranks them the same buries the one that matters.
func TestAccountWide_SensitivityChangesSeverity(t *testing.T) {
	mk := func(sensitive bool) types.Severity {
		got := Assess(Estate{Objects: []Object{{
			Platform: "snowflake", Name: "db.public.t", Type: "table", Sensitive: sensitive,
			Grants: []Grant{{Grantee: "PUBLIC", Privilege: "SELECT"}},
		}}}, fixedNow())
		f := has(got, "dataplatform::account-wide-grant")
		if f == nil {
			t.Fatalf("no account-wide finding (sensitive=%v): %v", sensitive, rules(got))
		}
		return f.Severity
	}
	if s, ns := mk(true), mk(false); s.Rank() <= ns.Rank() {
		t.Errorf("regulated data ranked %s, ordinary data %s — regulated must outrank", s, ns)
	}
}

// THE VERB MUST FOLLOW THE PRIVILEGE.
//
// A public INSERT is a real problem, but reporting it as "readable" is a false statement about our own
// evidence — precisely what every other refusal in this package exists to prevent.
func TestWriteOnlyPublicGrant_IsNotDescribedAsReadable(t *testing.T) {
	got := Assess(Estate{Objects: []Object{{
		Platform: "postgres", Name: "public.events", Type: "table",
		Grants: []Grant{{Grantee: "PUBLIC", Privilege: "INSERT"}},
	}}}, fixedNow())
	f := has(got, "dataplatform::account-wide-grant")
	if f == nil {
		t.Fatalf("a public INSERT was not reported at all: %v", rules(got))
	}
	if strings.Contains(f.Title, "readable") {
		t.Errorf("title claims the data is readable from an INSERT-only grant: %q", f.Title)
	}
	if !strings.Contains(f.Title, "writable") {
		t.Errorf("title does not say the data is writable: %q", f.Title)
	}
}

// GROUNDING: SENSITIVITY IS DECLARED, NEVER INFERRED FROM A NAME.
//
// A table called "customers" is not evidence that it holds customer data. Guessing here would either cry
// wolf on a lookup table or, worse, teach a reader that our sensitivity labels mean something they do not.
func TestSensitivity_IsNotGuessedFromTheName(t *testing.T) {
	got := Assess(Estate{
		OrgDomains: []string{"acme.com"},
		Objects: []Object{{
			Platform: "snowflake", Name: "prod.public.customers_pii_ssn", Type: "table",
			// Sensitive deliberately NOT declared.
			Grants: []Grant{{Grantee: "contractor@other-corp.com", GranteeType: "user", Privilege: "SELECT"}},
		}},
	}, fixedNow())
	if f := has(got, "dataplatform::external-grant-on-sensitive"); f != nil {
		t.Error("inferred sensitivity from the table NAME — a name is not a classification")
	}
}

// GROUNDING: "EXTERNAL" IS UNKNOWABLE WITHOUT KNOWING WHO IS INTERNAL.
//
// The same grant must be silent with no org domains and reported with them. A test that only checked one
// side would pass on an assessor that always guessed.
func TestExternalGrant_RequiresOrgDomains(t *testing.T) {
	obj := Object{
		Platform: "snowflake", Name: "prod.public.customers", Type: "table", Sensitive: true,
		Grants: []Grant{{Grantee: "contractor@other-corp.com", GranteeType: "user", Privilege: "SELECT"}},
	}
	if f := has(Assess(Estate{Objects: []Object{obj}}, fixedNow()), "dataplatform::external-grant-on-sensitive"); f != nil {
		t.Error("called a grantee external with no org domains supplied — that is a guess, not a finding")
	}
	if f := has(Assess(Estate{Objects: []Object{obj}, OrgDomains: []string{"acme.com"}}, fixedNow()),
		"dataplatform::external-grant-on-sensitive"); f == nil {
		t.Error("with org domains supplied, an outside grantee on regulated data was missed")
	}
}

// An internal grantee — including a subdomain — is not external.
func TestInternalGrantee_IsNotExternal(t *testing.T) {
	for _, who := range []string{"analyst@acme.com", "etl@data.acme.com", "analyst_role"} {
		got := Assess(Estate{
			OrgDomains: []string{"acme.com"},
			Objects: []Object{{
				Platform: "snowflake", Name: "prod.public.customers", Type: "table", Sensitive: true,
				Grants: []Grant{{Grantee: who, Privilege: "SELECT"}},
			}},
		}, fixedNow())
		if f := has(got, "dataplatform::external-grant-on-sensitive"); f != nil {
			t.Errorf("%q was reported as outside the organisation", who)
		}
	}
}

// GROUNDING: UNKNOWN IS NOT UNUSED.
//
// A warehouse that does not record last-use tells us nothing about whether a grant is stale. Reporting
// it as stale would be inventing an observation we never made.
func TestStaleGrant_RequiresALastUsedTimestamp(t *testing.T) {
	mk := func(lastUsed string) []types.Finding {
		return Assess(Estate{Objects: []Object{{
			Platform: "snowflake", Name: "db.public.t", Type: "table",
			Grants: []Grant{{Grantee: "old_role", Privilege: "SELECT", LastUsed: lastUsed}},
		}}}, fixedNow())
	}
	if f := has(mk(""), "dataplatform::stale-grant"); f != nil {
		t.Error("a grant with NO recorded last-use was reported as stale — unknown is not unused")
	}
	if f := has(mk("garbage"), "dataplatform::stale-grant"); f != nil {
		t.Error("an unparseable timestamp was treated as stale")
	}
	if f := has(mk("2027-01-01"), "dataplatform::stale-grant"); f != nil {
		t.Error("a FUTURE timestamp was treated as stale — that is bad data, not old access")
	}
	if f := has(mk("2026-08-10"), "dataplatform::stale-grant"); f != nil {
		t.Error("a grant used 4 days ago was reported as stale")
	}
	if f := has(mk("2026-01-01"), "dataplatform::stale-grant"); f == nil {
		t.Error("a grant unused for 7 months was NOT reported as stale")
	}
}

// The admin who is supposed to own the table is not privilege sprawl. Without this the check would fire
// on every correctly-administered warehouse, which is how a useful signal becomes noise people mute.
func TestWriteOnSensitive_ExemptsAdminRoles(t *testing.T) {
	mk := func(who string) *types.Finding {
		return has(Assess(Estate{Objects: []Object{{
			Platform: "snowflake", Name: "prod.public.customers", Type: "table", Sensitive: true,
			Grants: []Grant{{Grantee: who, Privilege: "OWNERSHIP"}},
		}}}, fixedNow()), "dataplatform::write-access-on-sensitive")
	}
	for _, admin := range []string{"ACCOUNTADMIN", "SYSADMIN", "postgres", "db_admin"} {
		if mk(admin) != nil {
			t.Errorf("%q flagged for holding ownership — that is the DBA doing their job", admin)
		}
	}
	if mk("intern_role") == nil {
		t.Error("a non-admin role holding OWNERSHIP on regulated data was NOT flagged")
	}
}

// Findings must be actionable on their own: the endpoint has to identify the object unambiguously,
// because that is what a responder searches for and what the platform attributes on.
func TestFindings_NameTheObjectUnambiguously(t *testing.T) {
	got := Assess(Estate{Objects: []Object{{
		Platform: "snowflake", Name: "analytics.public.customers", Type: "table", Sensitive: true,
		Grants: []Grant{{Grantee: "allUsers", Privilege: "SELECT"}},
	}}}, fixedNow())
	if len(got) == 0 {
		t.Fatal("no findings")
	}
	f := got[0]
	if f.Endpoint != "snowflake:analytics.public.customers" {
		t.Errorf("endpoint = %q, want the platform-qualified object name", f.Endpoint)
	}
	if f.Compliance == nil || len(f.Compliance.SOC2) == 0 {
		t.Error("no compliance nexus — the finding cannot flow into the evidence pack")
	}
	if f.Compliance.GDPR == nil {
		t.Error("regulated data exposed to the internet cites no privacy control")
	}
	if f.Tool != "dataplatform" || f.VerificationStatus != types.VerificationVerified {
		t.Errorf("tool/verification = %s/%s", f.Tool, f.VerificationStatus)
	}
}

// A declared-but-empty estate, an unnamed object, and no grants must all be silent rather than erroring
// or inventing — the shapes a real export produces on a quiet day.
func TestDegenerateInputs_AreSilent(t *testing.T) {
	for name, est := range map[string]Estate{
		"empty":          {},
		"no grants":      {Objects: []Object{{Platform: "snowflake", Name: "db.t"}}},
		"unnamed object": {Objects: []Object{{Platform: "snowflake", Grants: []Grant{{Grantee: "allUsers", Privilege: "SELECT"}}}}},
	} {
		if got := Assess(est, fixedNow()); len(got) != 0 {
			t.Errorf("%s produced findings: %v", name, rules(got))
		}
	}
}

// Worst first. A queue that leads with a low-severity stale grant while the internet reads the customer
// table is worse than no ordering at all.
func TestFindings_AreOrderedWorstFirst(t *testing.T) {
	got := Assess(Estate{Objects: []Object{
		{Platform: "snowflake", Name: "db.public.a", Type: "table",
			Grants: []Grant{{Grantee: "old_role", Privilege: "SELECT", LastUsed: "2026-01-01"}}},
		{Platform: "bigquery", Name: "proj.ds.customers", Type: "table", Sensitive: true,
			Grants: []Grant{{Grantee: "allUsers", Privilege: "SELECT"}}},
	}}, fixedNow())
	if len(got) < 2 {
		t.Fatalf("expected both findings, got %v", rules(got))
	}
	if got[0].Severity != types.SeverityCritical {
		t.Errorf("leads with %s (%s); the internet-readable table must come first",
			got[0].Severity, got[0].RuleID)
	}
}

// ── DISCOVERED SENSITIVITY (dataclass wiring) ────────────────────────────────────────────────────
//
// The point of the whole substrate: a crown jewel discovered from the data, not declared on a checkbox.

// A table nobody declared sensitive, whose sampled column holds real SSNs, must be treated as sensitive
// — and the account-wide-grant on it must escalate to the sensitive severity it now deserves.
func TestClassify_DiscoveredSensitivityDrivesTheAssessment(t *testing.T) {
	est := Estate{Objects: []Object{{
		Platform: "snowflake", Name: "prod.public.users", Type: "table",
		// NOT declared sensitive.
		Columns: []dataclass.Column{{Name: "national_number", Values: []string{"123-45-6789", "078-05-1120"}}},
		Grants:  []Grant{{Grantee: "PUBLIC", Privilege: "SELECT"}},
	}}}
	classified, disc := Classify(est)
	if !classified.Objects[0].Sensitive {
		t.Fatal("an object with sampled SSN values was not discovered sensitive")
	}
	if len(disc) != 1 || len(disc[0].Evidence) == 0 {
		t.Fatalf("discovery not recorded with evidence: %+v", disc)
	}
	// The account-wide finding must now carry the sensitive (high) severity, not the ordinary (medium).
	f := has(Assess(classified, fixedNow()), "dataplatform::account-wide-grant")
	if f == nil || f.Severity != types.SeverityHigh {
		t.Errorf("account-wide grant on DISCOVERED-sensitive data did not escalate: %+v", f)
	}
}

// A column merely NAMED like PII, with no values, is a suspicion — NOT enough to mint a crown jewel.
// Treating a name as proof is the exact inference the package refuses.
func TestClassify_NameOnlySignalDoesNotMintACrownJewel(t *testing.T) {
	est := Estate{Objects: []Object{{
		Platform: "snowflake", Name: "prod.public.t", Type: "table",
		Columns: []dataclass.Column{{Name: "ssn"}}, // named, no values
	}}}
	classified, disc := Classify(est)
	if classified.Objects[0].Sensitive {
		t.Error("a name-only signal flipped the object to sensitive — that is inference, not discovery")
	}
	if len(disc) != 0 {
		t.Errorf("a name-only signal produced a discovery: %+v", disc)
	}
}

// Discovery UPGRADES, never DOWNGRADES. A declared-sensitive object whose sample happens to show nothing
// stays sensitive — a few sampled rows are not proof the column is clean.
func TestClassify_NeverDowngradesADeclaration(t *testing.T) {
	est := Estate{Objects: []Object{{
		Platform: "snowflake", Name: "prod.public.t", Type: "table", Sensitive: true,
		Columns: []dataclass.Column{{Name: "widget_count", Values: []string{"3", "7"}}},
	}}}
	classified, _ := Classify(est)
	if !classified.Objects[0].Sensitive {
		t.Error("a clean sample cleared a customer's sensitive declaration")
	}
}

// No sampled columns → unchanged, no discoveries. Purely additive.
func TestClassify_NoColumnsIsANoOp(t *testing.T) {
	est := Estate{Objects: []Object{{Platform: "snowflake", Name: "t", Grants: []Grant{{Grantee: "PUBLIC", Privilege: "SELECT"}}}}}
	classified, disc := Classify(est)
	if disc != nil {
		t.Errorf("an estate with no sampled columns produced discoveries: %+v", disc)
	}
	if classified.Objects[0].Sensitive {
		t.Error("an object with no columns was marked sensitive")
	}
}
