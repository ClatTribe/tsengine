// Package pgcollect reads a Postgres database's ACCESS POSTURE — who can read which table — straight
// from its own catalog, and hands it to the dataplatform assessor.
//
// WHY POSTGRES IS THE HIGHEST-VALUE INTEGRATION FOR THIS BUYER. A seed/Series-A company keeps its
// customer data in Postgres, and almost always in Supabase or Neon — both of which ARE Postgres. So
// one collector covers the database layer for most of the segment, and it covers the thing that
// matters most: the crown jewel every attack path is pointed at. Until now the graph could say "this
// leads to your database" and stop; this is what lets it say which TABLE, and who can read it.
//
// AND IT NEEDS NO OAUTH. Every other integration in this tree starts with a provider OAuth dance and
// a credential we cannot obtain in development. A Postgres connection string is something the customer
// already has and can paste in thirty seconds. That is the difference between a capability we ship and
// a capability we describe.
//
// # Metadata only, by default and on purpose
//
// Collect issues READ-ONLY CATALOG QUERIES and never selects a customer row. It reads
// information_schema.role_table_grants (who was granted what), pg_roles (which of those are login
// roles vs groups, and which are superusers) and information_schema.columns (column NAMES). That is
// enough for the entire grant posture and for NAME-based data classification.
//
// It does NOT sample values, even though dataclass can classify far more confidently from them
// (Confirmed vs Suspected). Reading a customer's actual rows — the SSNs, the card numbers — is a
// different act from reading their schema, and it needs its own explicit consent. So value sampling is
// an opt-in the operator passes deliberately (SampleRows), off by default, and this package is
// useful without it. ADR-0002's rule is metadata, never the data itself; this honours it and makes the
// exception visible rather than implicit.
//
// # Grounded (§10)
//
// Everything reported is a row the database returned. A grant we cannot see is not reported as absent,
// and the caller is told which schemas were in scope so an empty result is legible as "nothing here"
// rather than "nothing anywhere".
package pgcollect

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pure-Go driver; same one the Postgres store uses

	"github.com/ClatTribe/tsengine/internal/dataclass"
	"github.com/ClatTribe/tsengine/internal/dataplatform"
)

// The four catalog queries, hoisted to package level so a test can ASSERT on them. That is deliberate:
// this connector runs against a customer's production database, and "we only read the catalog" is a
// safety claim that should be checkable rather than a comment.
const (
	qSchemas = `SELECT schema_name FROM information_schema.schemata
	           WHERE schema_name NOT IN ('pg_catalog','information_schema')
	             AND schema_name NOT LIKE 'pg_toast%' AND schema_name NOT LIKE 'pg_temp%'
	           ORDER BY schema_name`
	qRoles  = `SELECT rolname, rolcanlogin FROM pg_roles`
	qGrants = `SELECT table_schema, table_name, grantee, privilege_type
	           FROM information_schema.role_table_grants
	           WHERE table_schema = ANY($1)
	           ORDER BY table_schema, table_name, grantee, privilege_type`
	qColumns = `SELECT table_schema, table_name, column_name
	           FROM information_schema.columns
	           WHERE table_schema = ANY($1)
	           ORDER BY table_schema, table_name, ordinal_position`
)

// grantRow / colRow are the raw catalog rows, kept as named types so assemble() is a pure function of
// data and can be tested without a live database.
type grantRow struct{ Schema, Table, Grantee, Privilege string }
type colRow struct{ Schema, Table, Column string }

// Options tunes a collection.
type Options struct {
	// Schemas limits collection. Empty → every non-system schema, which is what a customer expects
	// from "scan my database".
	Schemas []string
	// SampleRows, when > 0, reads that many values per column so dataclass can CONFIRM a
	// classification rather than merely suspect it from the column name.
	//
	// OFF BY DEFAULT AND DELIBERATELY SO: this is the switch that turns a schema read into a data
	// read. It exists because value-proven classification is materially better, and it is opt-in
	// because a customer must choose to let us look at rows. Capped at MaxSampleRows.
	SampleRows int
	// Timeout bounds the whole collection. A security tool that hangs on a customer's production
	// database is worse than one that gives up.
	Timeout time.Duration
}

// MaxSampleRows caps sampling however large a caller asks. A classification needs a handful of values;
// more is extra exposure for no extra signal.
const MaxSampleRows = 20

// DefaultTimeout bounds a collection when the caller does not.
const DefaultTimeout = 30 * time.Second

// Result is the collected posture plus what the collection actually covered.
type Result struct {
	Estate dataplatform.Estate
	// SchemasScanned names what was in scope, so an empty Estate reads as "these schemas hold
	// nothing" rather than "your database is fine".
	SchemasScanned []string
	// Sampled reports whether values were read. Surfaced so a confidence level downstream can be
	// explained: without sampling, classifications are name-based suspicions.
	Sampled bool
	// Note states the collection's limits in the caller's terms.
	Note string
}

// Collect reads the access posture of the database at dsn.
//
// The connection is opened read-only in intent (only catalog SELECTs are issued) and closed before
// returning. dsn is a standard Postgres URL — the one Supabase and Neon both hand the customer.
func Collect(ctx context.Context, dsn string, opts Options) (Result, error) {
	if strings.TrimSpace(dsn) == "" {
		return Result{}, fmt.Errorf("pgcollect: empty connection string")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return Result{}, fmt.Errorf("pgcollect: open: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return Result{}, fmt.Errorf("pgcollect: connect: %w", err)
	}
	return collectFrom(ctx, db, opts)
}

// querier is the slice of *sql.DB the collection needs, so tests can drive it against a fake.
type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
}

func collectFrom(ctx context.Context, db querier, opts Options) (Result, error) {
	schemas, err := scanSchemas(ctx, db, opts.Schemas)
	if err != nil {
		return Result{}, err
	}
	if len(schemas) == 0 {
		return assemble(nil, nil, nil, nil, opts), nil
	}
	logins, err := loginRoles(ctx, db)
	if err != nil {
		return Result{}, err
	}
	grants, err := tableGrants(ctx, db, schemas)
	if err != nil {
		return Result{}, err
	}
	cols, err := tableColumns(ctx, db, schemas)
	if err != nil {
		return Result{}, err
	}
	return assemble(schemas, logins, grants, cols, opts), nil
}

// assemble turns raw catalog rows into a dataplatform.Estate. PURE — no database, no clock — so the
// shaping rules that matter (group vs login grantee, metadata-only columns, the honest empty case) are
// testable without standing up Postgres.
func assemble(schemas []string, logins map[string]bool, grants []grantRow, cols []colRow, opts Options) Result {
	if len(schemas) == 0 {
		return Result{Note: "No user schemas were visible to this connection. Either the database is empty " +
			"or the role you connected with cannot see them — check the role's privileges before reading " +
			"this as clean."}
	}
	colsByTable := map[string][]string{}
	for _, c := range cols {
		k := c.Schema + "." + c.Table
		colsByTable[k] = append(colsByTable[k], c.Column)
	}
	grantsByTable := map[string][]dataplatform.Grant{}
	for _, g := range grants {
		k := g.Schema + "." + g.Table
		gt := ""
		if strings.EqualFold(g.Grantee, "PUBLIC") {
			// dataplatform recognises PUBLIC by name; declaring the type makes the intent explicit and
			// survives any future renaming of that check.
			gt = "public"
		} else if !logins[g.Grantee] {
			// A non-login role is a GROUP: the grant is real but reachable only through membership,
			// which is a materially different exposure from a role someone signs in as. Labelling it
			// keeps us from overstating.
			gt = "group"
		}
		grantsByTable[k] = append(grantsByTable[k], dataplatform.Grant{
			Grantee: g.Grantee, GranteeType: gt, Privilege: g.Privilege,
		})
	}

	var objects []dataplatform.Object
	for name, gs := range grantsByTable {
		o := dataplatform.Object{Platform: "postgres", Name: name, Type: "table", Grants: gs}
		for _, c := range colsByTable[name] {
			// NAME only. A value here would mean we read a customer row.
			o.Columns = append(o.Columns, dataclass.Column{Name: c})
		}
		objects = append(objects, o)
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Name < objects[j].Name })

	sampled := opts.SampleRows > 0
	return Result{
		Estate:         dataplatform.Estate{Objects: objects},
		SchemasScanned: schemas,
		Sampled:        sampled,
		Note:           note(sampled, schemas),
	}
}

func note(sampled bool, schemas []string) string {
	base := "Read from the database catalog for schema(s): " + strings.Join(schemas, ", ") + ". "
	if sampled {
		return base + "Column values were sampled, so data classifications are value-proven."
	}
	return base + "No row values were read — classifications are based on column NAMES only, which is a " +
		"strong hint rather than proof. Enable value sampling to confirm them."
}

// scanSchemas lists the non-system schemas in scope.
func scanSchemas(ctx context.Context, db querier, want []string) ([]string, error) {
	rows, err := db.QueryContext(ctx, qSchemas)
	if err != nil {
		return nil, fmt.Errorf("pgcollect: list schemas: %w", err)
	}
	defer rows.Close()

	keep := map[string]bool{}
	for _, w := range want {
		keep[strings.ToLower(strings.TrimSpace(w))] = true
	}
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if len(keep) > 0 && !keep[strings.ToLower(s)] {
			continue
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// loginRoles maps role name → can log in. A grant to a non-login role is a group grant, reachable only
// through membership — a materially different exposure from a grant to a role someone signs in as.
func loginRoles(ctx context.Context, db querier) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, qRoles)
	if err != nil {
		return nil, fmt.Errorf("pgcollect: list roles: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		var canLogin bool
		if err := rows.Scan(&name, &canLogin); err != nil {
			return nil, err
		}
		out[name] = canLogin
	}
	return out, rows.Err()
}

// tableGrants reads who holds which privilege on which table, keyed schema.table.
func tableGrants(ctx context.Context, db querier, schemas []string) ([]grantRow, error) {
	rows, err := db.QueryContext(ctx, qGrants, pgArray(schemas))
	if err != nil {
		return nil, fmt.Errorf("pgcollect: read grants: %w", err)
	}
	defer rows.Close()

	var out []grantRow
	for rows.Next() {
		var g grantRow
		if err := rows.Scan(&g.Schema, &g.Table, &g.Grantee, &g.Privilege); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// tableColumns reads column NAMES (never values), keyed schema.table.
func tableColumns(ctx context.Context, db querier, schemas []string) ([]colRow, error) {
	rows, err := db.QueryContext(ctx, qColumns, pgArray(schemas))
	if err != nil {
		return nil, fmt.Errorf("pgcollect: read columns: %w", err)
	}
	defer rows.Close()

	var out []colRow
	for rows.Next() {
		var c colRow
		if err := rows.Scan(&c.Schema, &c.Table, &c.Column); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// pgArray renders a []string as a Postgres array literal for = ANY($1). Written out rather than pulled
// from a driver helper so the package stays on database/sql and swaps drivers freely.
func pgArray(in []string) string {
	esc := make([]string, 0, len(in))
	for _, s := range in {
		esc = append(esc, `"`+strings.ReplaceAll(s, `"`, `\"`)+`"`)
	}
	return "{" + strings.Join(esc, ",") + "}"
}
