package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo → keeps the static binary)

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// SQLite is a durable, indexed Store backed by an embedded SQLite database — the
// production single-box backend (real ACID + per-row writes + WAL, vs the file store's
// whole-snapshot rewrite). Each entity is stored as a JSON blob in a row keyed/indexed by
// its tenant + lookup keys, so the struct serialization is identical to the other stores
// (the conformance suite holds it to the same contract) and the schema ports to Postgres
// (TEXT→JSONB, same SQL) when scaling out — the agreed "architect to scale" path.
type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens (creating if absent) a SQLite store at path and ensures the schema.
func OpenSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite %s: %w", path, err)
	}
	// One writer (modernc serializes cleanly at MaxOpenConns=1 — no "database is locked"),
	// WAL for durable concurrent reads, a busy timeout as a belt-and-suspenders.
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON"} {
		if _, err := db.Exec(pragma); err != nil {
			return nil, fmt.Errorf("store: sqlite pragma: %w", err)
		}
	}
	if err := initSchema(db); err != nil {
		return nil, err
	}
	return &SQLite{db: db}, nil
}

// Close releases the database handle.
func (s *SQLite) Close() error { return s.db.Close() }

func initSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS tenants     (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS connections (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS assets      (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS engagements (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS findings    (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS actions     (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS controls    (tenant_id TEXT, framework TEXT, control_id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,framework,control_id));
CREATE TABLE IF NOT EXISTS incidents   (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS risks       (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS audits      (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS policies    (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS ignores     (tenant_id TEXT, issue_key TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,issue_key));
CREATE TABLE IF NOT EXISTS exclusions  (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS runtimeevts (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS pentests    (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS reviews     (tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS apps        (tenant_id TEXT, provider TEXT, app_id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,provider,app_id));
CREATE TABLE IF NOT EXISTS users       (id TEXT PRIMARY KEY, tenant_id TEXT, email TEXT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions    (token TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);
`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("store: sqlite schema: %w", err)
	}
	return nil
}

// --- small JSON helpers ---

func enc(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// listJSON runs query (one column: the JSON data) and decodes each row into a fresh T.
func listJSON[T any](ctx context.Context, db *sql.DB, query string, args ...any) ([]T, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var v T
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// getJSON decodes a single row's JSON into v, or returns ErrNotFound.
func getJSON(ctx context.Context, db *sql.DB, v any, query string, args ...any) error {
	var data string
	switch err := db.QueryRowContext(ctx, query, args...).Scan(&data); {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return err
	}
	return json.Unmarshal([]byte(data), v)
}

// --- tenants ---

func (s *SQLite) PutTenant(ctx context.Context, t platform.Tenant) error {
	d, err := enc(t)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO tenants(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, t.ID, d)
	return err
}

func (s *SQLite) GetTenant(ctx context.Context, id string) (platform.Tenant, error) {
	var t platform.Tenant
	err := getJSON(ctx, s.db, &t, `SELECT data FROM tenants WHERE id=?`, id)
	return t, err
}

func (s *SQLite) ListTenants(ctx context.Context) ([]platform.Tenant, error) {
	return listJSON[platform.Tenant](ctx, s.db, `SELECT data FROM tenants ORDER BY rowid`)
}

// --- connections / assets / engagements / findings / actions / incidents / reviews
//     (all upsert by (tenant_id,id), list by tenant in insertion order) ---

// upsertTID runs a fixed (compile-time constant) "INSERT … ON CONFLICT(tenant_id,id)"
// upsert. The query is always a string literal from the caller — never built from input —
// so it carries no injection risk.
func (s *SQLite) upsertTID(ctx context.Context, query, tenant, id string, v any) error {
	d, err := enc(v)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, query, tenant, id, d)
	return err
}

func (s *SQLite) PutConnection(ctx context.Context, c platform.Connection) error {
	return s.upsertTID(ctx, `INSERT INTO connections(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, c.TenantID, c.ID, c)
}
func (s *SQLite) ListConnections(ctx context.Context, tenantID string) ([]platform.Connection, error) {
	return listJSON[platform.Connection](ctx, s.db, `SELECT data FROM connections WHERE tenant_id=? ORDER BY rowid`, tenantID)
}

func (s *SQLite) PutAsset(ctx context.Context, a platform.Asset) error {
	return s.upsertTID(ctx, `INSERT INTO assets(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, a.TenantID, a.ID, a)
}
func (s *SQLite) ListAssets(ctx context.Context, tenantID string) ([]platform.Asset, error) {
	return listJSON[platform.Asset](ctx, s.db, `SELECT data FROM assets WHERE tenant_id=? ORDER BY rowid`, tenantID)
}

func (s *SQLite) PutEngagement(ctx context.Context, e platform.Engagement) error {
	return s.upsertTID(ctx, `INSERT INTO engagements(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, e.TenantID, e.ID, e)
}
func (s *SQLite) ListEngagements(ctx context.Context, tenantID string) ([]platform.Engagement, error) {
	return listJSON[platform.Engagement](ctx, s.db, `SELECT data FROM engagements WHERE tenant_id=? ORDER BY rowid`, tenantID)
}

func (s *SQLite) PutFinding(ctx context.Context, tenantID string, f types.Finding) error {
	return s.upsertTID(ctx, `INSERT INTO findings(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, tenantID, f.ID, f)
}
func (s *SQLite) ListFindings(ctx context.Context, tenantID string, filter FindingFilter) ([]types.Finding, error) {
	all, err := listJSON[types.Finding](ctx, s.db, `SELECT data FROM findings WHERE tenant_id=? ORDER BY rowid`, tenantID)
	if err != nil {
		return nil, err
	}
	// Filter in Go to match the Memory store's semantics exactly.
	var out []types.Finding
	for _, f := range all {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if filter.Status != "" && string(f.VerificationStatus) != filter.Status {
			continue
		}
		if filter.AssetID != "" { // engine findings don't carry an asset id yet
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func (s *SQLite) PutAction(ctx context.Context, a platform.Action) error {
	return s.upsertTID(ctx, `INSERT INTO actions(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, a.TenantID, a.ID, a)
}
func (s *SQLite) GetAction(ctx context.Context, tenantID, id string) (platform.Action, error) {
	var a platform.Action
	err := getJSON(ctx, s.db, &a, `SELECT data FROM actions WHERE tenant_id=? AND id=?`, tenantID, id)
	return a, err
}
func (s *SQLite) PendingApprovals(ctx context.Context, tenantID string) ([]platform.Action, error) {
	all, err := listJSON[platform.Action](ctx, s.db, `SELECT data FROM actions WHERE tenant_id=? ORDER BY rowid`, tenantID)
	if err != nil {
		return nil, err
	}
	var out []platform.Action
	for _, a := range all {
		if a.Status == platform.ActPendingApproval {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *SQLite) PutIncident(ctx context.Context, i platform.Incident) error {
	return s.upsertTID(ctx, `INSERT INTO incidents(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, i.TenantID, i.ID, i)
}
func (s *SQLite) ListIncidents(ctx context.Context, tenantID string) ([]platform.Incident, error) {
	return listJSON[platform.Incident](ctx, s.db, `SELECT data FROM incidents WHERE tenant_id=? ORDER BY rowid`, tenantID)
}
func (s *SQLite) PutRisk(ctx context.Context, r platform.Risk) error {
	return s.upsertTID(ctx, `INSERT INTO risks(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, r.TenantID, r.ID, r)
}
func (s *SQLite) ListRisks(ctx context.Context, tenantID string) ([]platform.Risk, error) {
	return listJSON[platform.Risk](ctx, s.db, `SELECT data FROM risks WHERE tenant_id=? ORDER BY rowid`, tenantID)
}
func (s *SQLite) PutAuditEngagement(ctx context.Context, e platform.AuditEngagement) error {
	return s.upsertTID(ctx, `INSERT INTO audits(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, e.TenantID, e.ID, e)
}
func (s *SQLite) ListAuditEngagements(ctx context.Context, tenantID string) ([]platform.AuditEngagement, error) {
	return listJSON[platform.AuditEngagement](ctx, s.db, `SELECT data FROM audits WHERE tenant_id=? ORDER BY rowid`, tenantID)
}
func (s *SQLite) PutPolicy(ctx context.Context, p platform.Policy) error {
	return s.upsertTID(ctx, `INSERT INTO policies(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, p.TenantID, p.ID, p)
}
func (s *SQLite) ListPolicies(ctx context.Context, tenantID string) ([]platform.Policy, error) {
	return listJSON[platform.Policy](ctx, s.db, `SELECT data FROM policies WHERE tenant_id=? ORDER BY rowid`, tenantID)
}

func (s *SQLite) PutIgnoreRule(ctx context.Context, ir platform.IgnoreRule) error {
	return s.upsertTID(ctx, `INSERT INTO ignores(tenant_id,issue_key,data) VALUES(?,?,?) ON CONFLICT(tenant_id,issue_key) DO UPDATE SET data=excluded.data`, ir.TenantID, ir.IssueKey, ir)
}
func (s *SQLite) ListIgnoreRules(ctx context.Context, tenantID string) ([]platform.IgnoreRule, error) {
	return listJSON[platform.IgnoreRule](ctx, s.db, `SELECT data FROM ignores WHERE tenant_id=? ORDER BY rowid`, tenantID)
}
func (s *SQLite) DeleteIgnoreRule(ctx context.Context, tenantID, issueKey string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ignores WHERE tenant_id=? AND issue_key=?`, tenantID, issueKey)
	return err
}

func (s *SQLite) PutExclusionRule(ctx context.Context, er platform.ExclusionRule) error {
	return s.upsertTID(ctx, `INSERT INTO exclusions(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, er.TenantID, er.ID, er)
}
func (s *SQLite) ListExclusionRules(ctx context.Context, tenantID string) ([]platform.ExclusionRule, error) {
	return listJSON[platform.ExclusionRule](ctx, s.db, `SELECT data FROM exclusions WHERE tenant_id=? ORDER BY rowid`, tenantID)
}
func (s *SQLite) DeleteExclusionRule(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM exclusions WHERE tenant_id=? AND id=?`, tenantID, id)
	return err
}

func (s *SQLite) PutRuntimeEvent(ctx context.Context, ev platform.RuntimeEvent) error {
	return s.upsertTID(ctx, `INSERT INTO runtimeevts(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, ev.TenantID, ev.ID, ev)
}
func (s *SQLite) ListRuntimeEvents(ctx context.Context, tenantID string) ([]platform.RuntimeEvent, error) {
	return listJSON[platform.RuntimeEvent](ctx, s.db, `SELECT data FROM runtimeevts WHERE tenant_id=? ORDER BY rowid`, tenantID)
}

func (s *SQLite) PutPentest(ctx context.Context, eng pentest.Engagement) error {
	return s.upsertTID(ctx, `INSERT INTO pentests(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, eng.TenantID, eng.ID, eng)
}
func (s *SQLite) ListPentests(ctx context.Context, tenantID string) ([]pentest.Engagement, error) {
	return listJSON[pentest.Engagement](ctx, s.db, `SELECT data FROM pentests WHERE tenant_id=? ORDER BY rowid`, tenantID)
}
func (s *SQLite) GetPentest(ctx context.Context, tenantID, id string) (pentest.Engagement, error) {
	var e pentest.Engagement
	err := getJSON(ctx, s.db, &e, `SELECT data FROM pentests WHERE tenant_id=? AND id=?`, tenantID, id)
	return e, err
}

func (s *SQLite) PutReviewRequest(ctx context.Context, r platform.ReviewRequest) error {
	return s.upsertTID(ctx, `INSERT INTO reviews(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, r.TenantID, r.ID, r)
}
func (s *SQLite) ListReviewRequests(ctx context.Context, tenantID string) ([]platform.ReviewRequest, error) {
	return listJSON[platform.ReviewRequest](ctx, s.db, `SELECT data FROM reviews WHERE tenant_id=? ORDER BY rowid`, tenantID)
}

// --- control state (keyed by tenant+framework+control) ---

func (s *SQLite) UpsertControlState(ctx context.Context, cs platform.ControlState) error {
	d, err := enc(cs)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO controls(tenant_id,framework,control_id,data) VALUES(?,?,?,?)
		 ON CONFLICT(tenant_id,framework,control_id) DO UPDATE SET data=excluded.data`,
		cs.TenantID, cs.Framework, cs.ControlID, d)
	return err
}
func (s *SQLite) Posture(ctx context.Context, tenantID, framework string) ([]platform.ControlState, error) {
	return listJSON[platform.ControlState](ctx, s.db, `SELECT data FROM controls WHERE tenant_id=? AND framework=? ORDER BY rowid`, tenantID, framework)
}

// --- third-party apps (replace the whole (tenant,provider) set atomically) ---

func (s *SQLite) ReplaceThirdPartyApps(ctx context.Context, tenantID, provider string, apps []platform.ThirdPartyApp) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM apps WHERE tenant_id=? AND provider=?`, tenantID, provider); err != nil {
		return err
	}
	for _, a := range apps {
		d, err := enc(a)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO apps(tenant_id,provider,app_id,data) VALUES(?,?,?,?)`, tenantID, provider, a.AppID, d); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *SQLite) ListThirdPartyApps(ctx context.Context, tenantID string) ([]platform.ThirdPartyApp, error) {
	return listJSON[platform.ThirdPartyApp](ctx, s.db, `SELECT data FROM apps WHERE tenant_id=? ORDER BY rowid`, tenantID)
}

// --- users & sessions ---

func (s *SQLite) PutUser(ctx context.Context, u platform.User) error {
	d, err := enc(u)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users(id,tenant_id,email,data) VALUES(?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET tenant_id=excluded.tenant_id, email=excluded.email, data=excluded.data`,
		u.ID, u.TenantID, u.Email, d)
	return err
}
func (s *SQLite) GetUser(ctx context.Context, id string) (platform.User, error) {
	var u platform.User
	err := getJSON(ctx, s.db, &u, `SELECT data FROM users WHERE id=?`, id)
	return u, err
}
func (s *SQLite) GetUserByEmail(ctx context.Context, email string) (platform.User, error) {
	var u platform.User
	err := getJSON(ctx, s.db, &u, `SELECT data FROM users WHERE lower(email)=lower(?) LIMIT 1`, email)
	return u, err
}
func (s *SQLite) ListUsers(ctx context.Context, tenantID string) ([]platform.User, error) {
	return listJSON[platform.User](ctx, s.db, `SELECT data FROM users WHERE tenant_id=? ORDER BY rowid`, tenantID)
}

func (s *SQLite) PutSession(ctx context.Context, sess platform.Session) error {
	d, err := enc(sess)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions(token,data) VALUES(?,?) ON CONFLICT(token) DO UPDATE SET data=excluded.data`, sess.Token, d)
	return err
}
func (s *SQLite) GetSession(ctx context.Context, token string) (platform.Session, error) {
	var sess platform.Session
	err := getJSON(ctx, s.db, &sess, `SELECT data FROM sessions WHERE token=?`, token)
	return sess, err
}
func (s *SQLite) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token=?`, token)
	return err
}
