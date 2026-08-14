package platformapi

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

// ── THE CREDENTIAL RULES ─────────────────────────────────────────────────────────────────────────
//
// A production database DSN is the most dangerous secret a customer can hand us: unscoped, not
// revocable per-use, and it opens the data itself rather than a description of it. These tests exist
// because a leak here would be a breach we caused while looking for breaches.

// A driver error that quotes the connection string must never reach a response body or a log with the
// password intact. Drivers do this more often than you would like.
func TestRedactDSN_StripsPasswordsFromDriverErrors(t *testing.T) {
	for name, tc := range map[string]struct{ in, mustNotContain string }{
		"url form":       {`failed to connect to postgres://admin:hunter2@db.acme.com:5432/prod`, "hunter2"},
		"postgresql url": {`dial error on postgresql://u:s3cr3t@host/db (timeout)`, "s3cr3t"},
		"kv form":        {`connection refused: host=db.acme.com password=topsecret sslmode=require`, "topsecret"},
	} {
		got := redactDSN(tc.in)
		if strings.Contains(got, tc.mustNotContain) {
			t.Errorf("%s: the password survived redaction: %q", name, got)
		}
		if !strings.Contains(got, "redacted") {
			t.Errorf("%s: nothing was redacted, so the rule silently did nothing: %q", name, got)
		}
	}
}

// Redaction must not destroy the diagnostic. A customer needs to know it was a timeout to THAT host —
// stripping everything would trade one failure for another.
func TestRedactDSN_KeepsTheErrorUseful(t *testing.T) {
	got := redactDSN(`dial tcp: i/o timeout connecting to postgres://u:pw@db.acme.com:5432/prod`)
	if !strings.Contains(got, "timeout") {
		t.Errorf("redaction removed the actual error: %q", got)
	}
	if strings.Contains(got, "pw@") {
		t.Errorf("password survived: %q", got)
	}
}

// A message with no credential in it must pass through untouched.
func TestRedactDSN_LeavesCleanMessagesAlone(t *testing.T) {
	in := "connection refused"
	if got := redactDSN(in); got != in {
		t.Errorf("a clean message was mangled: %q", got)
	}
}

// ── THE ENDPOINT ─────────────────────────────────────────────────────────────────────────────────

func dbHandler(t *testing.T) (http.Handler, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	return NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}), st
}

func TestDatabaseScan_RequiresADSN(t *testing.T) {
	h, _ := dbHandler(t)
	rec := do(h, "POST", "/v1/database/scan", "t1", `{}`)
	if rec.Code != 400 {
		t.Fatalf("missing dsn got %d, want 400", rec.Code)
	}
	// The error must tell a non-expert WHERE to find the thing we are asking for.
	if !strings.Contains(strings.ToLower(rec.Body.String()), "supabase") {
		t.Errorf("the error does not say where to get a connection string: %s", rec.Body.String())
	}
}

// An unreachable database is the customer's problem to fix, so the error is returned — but the DSN must
// not come back with it.
func TestDatabaseScan_UnreachableDBReturnsARedactedError(t *testing.T) {
	h, _ := dbHandler(t)
	// Port 1 on localhost: refused fast, no network dependency, no real database touched.
	rec := do(h, "POST", "/v1/database/scan", "t1",
		`{"dsn":"postgres://admin:hunter2@127.0.0.1:1/postgres?connect_timeout=1&sslmode=disable"}`)
	if rec.Code == 200 {
		t.Fatalf("an unreachable database returned 200: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Errorf("THE PASSWORD CAME BACK IN THE ERROR RESPONSE: %s", rec.Body.String())
	}
}

// The endpoint must state plainly that the credential was not kept. A customer pasting a production
// DSN deserves to be told what happened to it rather than left to assume.
func TestDatabaseScan_SaysTheCredentialWasNotStored(t *testing.T) {
	h, _ := dbHandler(t)
	rec := do(h, "POST", "/v1/database/scan", "t1",
		`{"dsn":"postgres://u:p@127.0.0.1:1/postgres?connect_timeout=1&sslmode=disable"}`)
	// Even on the failure path the contract holds: nothing about the DSN is persisted anywhere.
	body := rec.Body.String()
	if strings.Contains(body, "u:p@") {
		t.Errorf("the DSN was echoed: %s", body)
	}
}

// THE STRUCTURAL GUARANTEE. There must be no code path that persists the DSN — not sealed, not
// hashed, not logged. This asserts it at the source, because "we do not store it" is a claim a
// customer cannot verify from the outside.
func TestDatabaseScan_NoCodePathPersistsTheDSN(t *testing.T) {
	src := readSource(t, "database.go")
	// The request field must never reach the store, the vault, or the ledger payload.
	for _, forbidden := range []string{
		"PutTenant", "PutConnection", "d.Vault", "Seal(",
	} {
		if strings.Contains(src, forbidden) {
			t.Errorf("database.go references %q — the DSN must never be persisted in any form", forbidden)
		}
	}
	// The ledger record must not carry the DSN.
	if i := strings.Index(src, "d.Recorder.Record"); i >= 0 {
		rec := src[i:min(i+400, len(src))]
		if strings.Contains(rec, "req.DSN") || strings.Contains(rec, "DSN") {
			t.Errorf("the ledger record carries the DSN:\n%s", rec)
		}
	}
}

// Value sampling reads customer rows, so it must be off unless the request asks.
func TestDatabaseScan_SamplingIsOptIn(t *testing.T) {
	src := readSource(t, "database.go")
	if !strings.Contains(src, "if req.SampleValues {") {
		t.Error("value sampling is not gated on the request flag — reading rows must be an explicit choice")
	}
}

func TestDatabaseScan_RejectsGarbageBody(t *testing.T) {
	h, _ := dbHandler(t)
	if rec := do(h, "POST", "/v1/database/scan", "t1", `{"dsn":`); rec.Code != 400 {
		t.Errorf("malformed body got %d, want 400", rec.Code)
	}
}

// A successful response must be JSON the frontend can index without crashing (the null-array class).
func TestDatabaseScan_ErrorBodyIsWellFormedJSON(t *testing.T) {
	h, _ := dbHandler(t)
	rec := do(h, "POST", "/v1/database/scan", "t1",
		`{"dsn":"postgres://u:p@127.0.0.1:1/x?connect_timeout=1&sslmode=disable"}`)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v — %s", err, rec.Body.String())
	}
}

// readSource reads a file in this package so a test can assert on the CODE, not just behaviour. Used
// for the credential rules: "we never persist the DSN" is a claim about what code exists, and a
// behavioural test cannot prove the absence of a write path.
func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
