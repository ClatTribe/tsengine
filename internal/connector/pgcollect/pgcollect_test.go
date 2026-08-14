package pgcollect

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/dataplatform"
)

// ── SAFETY: WHAT WE ARE AND ARE NOT ALLOWED TO READ ──────────────────────────────────────────────
//
// This connector runs against a customer's PRODUCTION database. The line between reading their SCHEMA
// and reading their DATA is the entire safety story, so it is asserted on the queries themselves
// rather than trusted to the implementation staying careful.

// THE ONE THAT MATTERS: every statement must target the catalog, and none may mutate. If this fails we
// are touching rows we were not invited to touch.
func TestQueries_TouchOnlyTheCatalogAndNeverMutate(t *testing.T) {
	for name, q := range map[string]string{
		"schemas": qSchemas, "roles": qRoles, "grants": qGrants, "columns": qColumns,
	} {
		low := strings.ToLower(q)
		if !strings.Contains(low, "information_schema") && !strings.Contains(low, "pg_roles") {
			t.Errorf("%s query does not target the catalog — it may be reading customer data:\n%s", name, q)
		}
		if !strings.HasPrefix(strings.TrimSpace(low), "select") {
			t.Errorf("%s query is not a SELECT: %s", name, q)
		}
		for _, forbidden := range []string{"insert ", "update ", "delete ", "drop ", "alter ", "create ", "truncate ", "grant ", "revoke "} {
			if strings.Contains(low, forbidden) {
				t.Errorf("%s query contains %q — this connector must be strictly read-only", name, forbidden)
			}
		}
	}
}

// Sampling is the switch that turns a schema read into a data read: off unless asked, and capped
// however large the ask.
func TestSampling_IsOffByDefaultAndCapped(t *testing.T) {
	if (Options{}).SampleRows != 0 {
		t.Error("value sampling defaults to ON — reading customer rows must be an explicit choice")
	}
	if MaxSampleRows > 20 {
		t.Errorf("MaxSampleRows = %d; a classification needs a handful of values, more is exposure for no signal", MaxSampleRows)
	}
}

// A metadata-only collection must never attach a VALUE to a column, because a value here means we read
// a customer row.
func TestAssemble_CarriesColumnNamesButNeverValues(t *testing.T) {
	res := assemble([]string{"public"},
		map[string]bool{"app_user": true},
		[]grantRow{{"public", "customers", "app_user", "SELECT"}},
		[]colRow{{"public", "customers", "email"}, {"public", "customers", "ssn"}},
		Options{})

	if len(res.Estate.Objects) != 1 {
		t.Fatalf("want 1 object, got %d", len(res.Estate.Objects))
	}
	o := res.Estate.Objects[0]
	if len(o.Columns) != 2 {
		t.Fatalf("want 2 column names, got %d", len(o.Columns))
	}
	for _, c := range o.Columns {
		if len(c.Values) != 0 {
			t.Errorf("column %q carries sampled values in a metadata-only collection", c.Name)
		}
	}
}

// ── HONEST REPORTING ─────────────────────────────────────────────────────────────────────────────

// Without sampling, classifications are name-based suspicions. The note must say so, or a customer
// reads a guess derived from a column name as a proven finding.
func TestNote_DistinguishesSampledFromNameOnly(t *testing.T) {
	nameOnly := note(false, []string{"public"})
	sampled := note(true, []string{"public"})

	if !strings.Contains(strings.ToLower(nameOnly), "no row values were read") {
		t.Errorf("the un-sampled note does not say values were not read: %q", nameOnly)
	}
	if !strings.Contains(strings.ToLower(nameOnly), "rather than proof") {
		t.Errorf("the un-sampled note presents name-based guesses as proof: %q", nameOnly)
	}
	if nameOnly == sampled {
		t.Error("sampled and un-sampled collections report identically — the confidence difference is invisible")
	}
	if !strings.Contains(nameOnly, "public") {
		t.Errorf("the note does not name the schemas covered, so an empty result is unreadable: %q", nameOnly)
	}
}

// THE HONEST EMPTY CASE. "Nothing found" and "this role cannot see anything" are different facts, and
// only one of them means the database is clean. Reporting the first when the truth is the second is a
// false all-clear on the customer's most sensitive system.
func TestAssemble_EmptyAdmitsItMayBeAPermissionProblem(t *testing.T) {
	res := assemble(nil, nil, nil, nil, Options{})
	if len(res.Estate.Objects) != 0 {
		t.Fatal("expected no objects")
	}
	low := strings.ToLower(res.Note)
	if !strings.Contains(low, "cannot see them") && !strings.Contains(low, "privileges") {
		t.Errorf("an empty scan did not raise the permission possibility: %q", res.Note)
	}
	if strings.Contains(low, "clean") && !strings.Contains(low, "before reading this as clean") {
		t.Errorf("an empty scan implied the database is clean: %q", res.Note)
	}
}

// ── COLLECTION SHAPE, END TO END ─────────────────────────────────────────────────────────────────

// The payoff: a real Postgres grant posture flows into the assessor and produces the finding.
func TestAssemble_PublicGrantReachesTheAssessor(t *testing.T) {
	res := assemble([]string{"public"},
		map[string]bool{"app_user": true},
		[]grantRow{
			{"public", "customers", "app_user", "SELECT"},
			{"public", "customers", "PUBLIC", "SELECT"},
		},
		[]colRow{{"public", "customers", "email"}},
		Options{})

	findings := dataplatform.Assess(res.Estate, dataplatform.Options{})
	var found bool
	for _, f := range findings {
		if strings.Contains(f.RuleID, "account-wide-grant") {
			found = true
		}
	}
	if !found {
		t.Errorf("a table granted to PUBLIC produced no account-wide finding: %+v", findings)
	}
}

// A non-login role is a GROUP — the grant is real but reachable only through membership, a materially
// different exposure from a role someone signs in as. Mislabelling it overstates the risk.
func TestAssemble_MarksNonLoginRolesAsGroups(t *testing.T) {
	res := assemble([]string{"public"},
		map[string]bool{"app_user": true, "readonly_grp": false},
		[]grantRow{
			{"public", "t", "app_user", "SELECT"},
			{"public", "t", "readonly_grp", "SELECT"},
		}, nil, Options{})

	byGrantee := map[string]string{}
	for _, g := range res.Estate.Objects[0].Grants {
		byGrantee[g.Grantee] = g.GranteeType
	}
	if byGrantee["readonly_grp"] != "group" {
		t.Errorf("a non-login role was not marked a group: %q", byGrantee["readonly_grp"])
	}
	if byGrantee["app_user"] == "group" {
		t.Error("a login role was mislabelled a group — that understates a directly-usable grant")
	}
}

// PUBLIC keeps its own type rather than being swept into "group", because its blast radius is
// categorically different: every role in the database, not the members of one.
func TestAssemble_PublicIsNotJustAnotherGroup(t *testing.T) {
	res := assemble([]string{"public"}, map[string]bool{},
		[]grantRow{{"public", "t", "PUBLIC", "SELECT"}}, nil, Options{})
	if got := res.Estate.Objects[0].Grants[0].GranteeType; got != "public" {
		t.Errorf("PUBLIC was typed %q — its blast radius is categorically wider than a group's", got)
	}
}

func TestAssemble_IsDeterministic(t *testing.T) {
	mk := func() Result {
		return assemble([]string{"public"}, map[string]bool{"a": true},
			[]grantRow{{"public", "z", "a", "SELECT"}, {"public", "a", "a", "SELECT"}}, nil, Options{})
	}
	first := mk()
	for i := 0; i < 5; i++ {
		got := mk()
		if len(got.Estate.Objects) != len(first.Estate.Objects) {
			t.Fatal("object count varies between runs")
		}
		for j := range got.Estate.Objects {
			if got.Estate.Objects[j].Name != first.Estate.Objects[j].Name {
				t.Fatalf("object order varies between runs: %s vs %s",
					got.Estate.Objects[j].Name, first.Estate.Objects[j].Name)
			}
		}
	}
}

func TestCollect_RejectsAnEmptyDSN(t *testing.T) {
	if _, err := Collect(context.Background(), "  ", Options{}); err == nil {
		t.Error("an empty connection string was accepted")
	}
}

func TestPgArray_QuotesAndEscapes(t *testing.T) {
	if got := pgArray([]string{"public", "my schema"}); got != `{"public","my schema"}` {
		t.Errorf("pgArray = %q", got)
	}
	if got := pgArray(nil); got != "{}" {
		t.Errorf("empty pgArray = %q", got)
	}
}
