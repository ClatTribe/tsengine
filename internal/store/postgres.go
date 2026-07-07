package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // pure-Go Postgres driver (CGO-free → keeps the static binary)

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Postgres is the durable, multi-node Store backed by PostgreSQL (e.g. Supabase / RDS / Neon) — the
// scale-out successor to the single-box SQLite store. It is a near-mechanical port: every entity is the
// SAME JSON blob in a row keyed by tenant + lookup keys (the conformance suite holds it to the identical
// contract), so the only dialect differences vs SQLite are the placeholder style (?→$N) and insertion
// ordering (SQLite rowid → an explicit `seq BIGSERIAL` column). pgRebind translates the shared SQLite-style
// queries; the upsert (ON CONFLICT … DO UPDATE SET data=excluded.data) is already valid Postgres.
//
// Unlike SQLite (single writer on a local disk), Postgres is the path to running MULTIPLE backend
// instances against one database. Selected via TSENGINE_PLATFORM_DB=postgres://… (store.Open routes it).
type Postgres struct {
	db *sql.DB
}

var _ Store = (*Postgres)(nil)

// OpenPostgres connects to a Postgres DSN (postgres://user:pass@host:5432/db?sslmode=require) and ensures
// the schema. The DSN is exactly what Supabase/RDS/Neon give you.
func OpenPostgres(dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("store: ping postgres: %w", err)
	}
	if err := initSchemaPG(db); err != nil {
		return nil, err
	}
	return &Postgres{db: db}, nil
}

// Close releases the database handle.
func (p *Postgres) Close() error { return p.db.Close() }

// pgRebind translates a shared SQLite-style query into Postgres: `rowid` (SQLite's implicit ordering
// column) → our explicit `seq`, and positional `?` → `$1, $2, …`. The queries are always string literals
// from this package (never built from input), and none contain a literal `?` inside a string, so the
// rewrite is safe. This lets the Postgres methods reuse the same query text as the SQLite store.
func pgRebind(q string) string {
	q = strings.ReplaceAll(q, "rowid", "seq")
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

func (p *Postgres) exec(ctx context.Context, query string, args ...any) error {
	_, err := p.db.ExecContext(ctx, pgRebind(query), args...)
	return err
}

func (p *Postgres) get(ctx context.Context, v any, query string, args ...any) error {
	return getJSON(ctx, p.db, v, pgRebind(query), args...)
}

// upsertTID mirrors SQLite.upsertTID for the (tenant_id,id) tables.
func (p *Postgres) upsertTID(ctx context.Context, query, tenant, id string, v any) error {
	d, err := enc(v)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, pgRebind(query), tenant, id, d)
	return err
}

func initSchemaPG(db *sql.DB) error {
	// `seq BIGSERIAL` gives each row a monotonically-increasing insertion order (Postgres has no rowid);
	// ON CONFLICT DO UPDATE keeps the original seq, so list-by-seq preserves insert order across upserts.
	const schema = `
CREATE TABLE IF NOT EXISTS tenants     (seq BIGSERIAL, id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS connections (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS assets      (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS engagements (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS findings    (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS actions     (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS controls    (seq BIGSERIAL, tenant_id TEXT, framework TEXT, control_id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,framework,control_id));
CREATE TABLE IF NOT EXISTS incidents   (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS risks       (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS ai_analyses (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS compliance_snaps (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS audits      (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS policies    (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS ignores     (seq BIGSERIAL, tenant_id TEXT, issue_key TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,issue_key));
CREATE TABLE IF NOT EXISTS exclusions  (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS runtimeevts (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS pentests    (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS reviews     (seq BIGSERIAL, tenant_id TEXT, id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS apps        (seq BIGSERIAL, tenant_id TEXT, provider TEXT, app_id TEXT, data TEXT NOT NULL, PRIMARY KEY(tenant_id,provider,app_id));
CREATE TABLE IF NOT EXISTS users       (seq BIGSERIAL, id TEXT PRIMARY KEY, tenant_id TEXT, email TEXT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions    (seq BIGSERIAL, token TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS operators   (seq BIGSERIAL, id TEXT PRIMARY KEY, email TEXT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS opsessions  (seq BIGSERIAL, token TEXT PRIMARY KEY, data TEXT NOT NULL);`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("store: postgres schema: %w", err)
	}
	return nil
}

// --- tenants ---

func (p *Postgres) PutTenant(ctx context.Context, t platform.Tenant) error {
	d, err := enc(t)
	if err != nil {
		return err
	}
	return p.exec(ctx, `INSERT INTO tenants(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, t.ID, d)
}
func (p *Postgres) GetTenant(ctx context.Context, id string) (platform.Tenant, error) {
	var t platform.Tenant
	err := p.get(ctx, &t, `SELECT data FROM tenants WHERE id=?`, id)
	return t, err
}
func (p *Postgres) ListTenants(ctx context.Context) ([]platform.Tenant, error) {
	return listJSON[platform.Tenant](ctx, p.db, pgRebind(`SELECT data FROM tenants ORDER BY rowid`))
}

// --- (tenant_id,id) entities ---

func (p *Postgres) PutConnection(ctx context.Context, c platform.Connection) error {
	return p.upsertTID(ctx, `INSERT INTO connections(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, c.TenantID, c.ID, c)
}
func (p *Postgres) ListConnections(ctx context.Context, tenantID string) ([]platform.Connection, error) {
	return listJSON[platform.Connection](ctx, p.db, pgRebind(`SELECT data FROM connections WHERE tenant_id=? ORDER BY rowid`), tenantID)
}
func (p *Postgres) DeleteConnection(ctx context.Context, tenantID, id string) error {
	return p.exec(ctx, `DELETE FROM connections WHERE tenant_id=? AND id=?`, tenantID, id)
}

func (p *Postgres) PutAsset(ctx context.Context, a platform.Asset) error {
	return p.upsertTID(ctx, `INSERT INTO assets(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, a.TenantID, a.ID, a)
}
func (p *Postgres) ListAssets(ctx context.Context, tenantID string) ([]platform.Asset, error) {
	return listJSON[platform.Asset](ctx, p.db, pgRebind(`SELECT data FROM assets WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

func (p *Postgres) PutEngagement(ctx context.Context, e platform.Engagement) error {
	return p.upsertTID(ctx, `INSERT INTO engagements(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, e.TenantID, e.ID, e)
}
func (p *Postgres) ListEngagements(ctx context.Context, tenantID string) ([]platform.Engagement, error) {
	return listJSON[platform.Engagement](ctx, p.db, pgRebind(`SELECT data FROM engagements WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

func (p *Postgres) PutFinding(ctx context.Context, tenantID string, f types.Finding) error {
	return p.upsertTID(ctx, `INSERT INTO findings(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, tenantID, f.ID, f)
}
func (p *Postgres) ListFindings(ctx context.Context, tenantID string, filter FindingFilter) ([]types.Finding, error) {
	all, err := listJSON[types.Finding](ctx, p.db, pgRebind(`SELECT data FROM findings WHERE tenant_id=? ORDER BY rowid`), tenantID)
	if err != nil {
		return nil, err
	}
	var out []types.Finding
	for _, f := range all {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if filter.Status != "" && string(f.VerificationStatus) != filter.Status {
			continue
		}
		if filter.AssetID != "" {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func (p *Postgres) PutAction(ctx context.Context, a platform.Action) error {
	return p.upsertTID(ctx, `INSERT INTO actions(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, a.TenantID, a.ID, a)
}
func (p *Postgres) GetAction(ctx context.Context, tenantID, id string) (platform.Action, error) {
	var a platform.Action
	err := p.get(ctx, &a, `SELECT data FROM actions WHERE tenant_id=? AND id=?`, tenantID, id)
	return a, err
}
func (p *Postgres) PendingApprovals(ctx context.Context, tenantID string) ([]platform.Action, error) {
	all, err := listJSON[platform.Action](ctx, p.db, pgRebind(`SELECT data FROM actions WHERE tenant_id=? ORDER BY rowid`), tenantID)
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
func (p *Postgres) ListActions(ctx context.Context, tenantID string) ([]platform.Action, error) {
	return listJSON[platform.Action](ctx, p.db, pgRebind(`SELECT data FROM actions WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

func (p *Postgres) PutIncident(ctx context.Context, i platform.Incident) error {
	return p.upsertTID(ctx, `INSERT INTO incidents(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, i.TenantID, i.ID, i)
}
func (p *Postgres) ListIncidents(ctx context.Context, tenantID string) ([]platform.Incident, error) {
	return listJSON[platform.Incident](ctx, p.db, pgRebind(`SELECT data FROM incidents WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

func (p *Postgres) PutRisk(ctx context.Context, r platform.Risk) error {
	return p.upsertTID(ctx, `INSERT INTO risks(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, r.TenantID, r.ID, r)
}
func (p *Postgres) ListRisks(ctx context.Context, tenantID string) ([]platform.Risk, error) {
	return listJSON[platform.Risk](ctx, p.db, pgRebind(`SELECT data FROM risks WHERE tenant_id=? ORDER BY rowid`), tenantID)
}
func (p *Postgres) PutAIAnalysis(ctx context.Context, a platform.AIAnalysis) error {
	return p.upsertTID(ctx, `INSERT INTO ai_analyses(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, a.TenantID, a.ID, a)
}
func (p *Postgres) ListAIAnalyses(ctx context.Context, tenantID string) ([]platform.AIAnalysis, error) {
	return listJSON[platform.AIAnalysis](ctx, p.db, pgRebind(`SELECT data FROM ai_analyses WHERE tenant_id=? ORDER BY rowid`), tenantID)
}
func (p *Postgres) PutComplianceSnapshot(ctx context.Context, s platform.ComplianceSnapshot) error {
	return p.upsertTID(ctx, `INSERT INTO compliance_snaps(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, s.TenantID, s.ID, s)
}
func (p *Postgres) ListComplianceSnapshots(ctx context.Context, tenantID string) ([]platform.ComplianceSnapshot, error) {
	return listJSON[platform.ComplianceSnapshot](ctx, p.db, pgRebind(`SELECT data FROM compliance_snaps WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

func (p *Postgres) PutAuditEngagement(ctx context.Context, e platform.AuditEngagement) error {
	return p.upsertTID(ctx, `INSERT INTO audits(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, e.TenantID, e.ID, e)
}
func (p *Postgres) ListAuditEngagements(ctx context.Context, tenantID string) ([]platform.AuditEngagement, error) {
	return listJSON[platform.AuditEngagement](ctx, p.db, pgRebind(`SELECT data FROM audits WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

func (p *Postgres) PutPolicy(ctx context.Context, pol platform.Policy) error {
	return p.upsertTID(ctx, `INSERT INTO policies(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, pol.TenantID, pol.ID, pol)
}
func (p *Postgres) ListPolicies(ctx context.Context, tenantID string) ([]platform.Policy, error) {
	return listJSON[platform.Policy](ctx, p.db, pgRebind(`SELECT data FROM policies WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

func (p *Postgres) PutIgnoreRule(ctx context.Context, ir platform.IgnoreRule) error {
	return p.upsertTID(ctx, `INSERT INTO ignores(tenant_id,issue_key,data) VALUES(?,?,?) ON CONFLICT(tenant_id,issue_key) DO UPDATE SET data=excluded.data`, ir.TenantID, ir.IssueKey, ir)
}
func (p *Postgres) ListIgnoreRules(ctx context.Context, tenantID string) ([]platform.IgnoreRule, error) {
	return listJSON[platform.IgnoreRule](ctx, p.db, pgRebind(`SELECT data FROM ignores WHERE tenant_id=? ORDER BY rowid`), tenantID)
}
func (p *Postgres) DeleteIgnoreRule(ctx context.Context, tenantID, issueKey string) error {
	return p.exec(ctx, `DELETE FROM ignores WHERE tenant_id=? AND issue_key=?`, tenantID, issueKey)
}

func (p *Postgres) PutExclusionRule(ctx context.Context, er platform.ExclusionRule) error {
	return p.upsertTID(ctx, `INSERT INTO exclusions(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, er.TenantID, er.ID, er)
}
func (p *Postgres) ListExclusionRules(ctx context.Context, tenantID string) ([]platform.ExclusionRule, error) {
	return listJSON[platform.ExclusionRule](ctx, p.db, pgRebind(`SELECT data FROM exclusions WHERE tenant_id=? ORDER BY rowid`), tenantID)
}
func (p *Postgres) DeleteExclusionRule(ctx context.Context, tenantID, id string) error {
	return p.exec(ctx, `DELETE FROM exclusions WHERE tenant_id=? AND id=?`, tenantID, id)
}

func (p *Postgres) PutRuntimeEvent(ctx context.Context, ev platform.RuntimeEvent) error {
	return p.upsertTID(ctx, `INSERT INTO runtimeevts(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, ev.TenantID, ev.ID, ev)
}
func (p *Postgres) ListRuntimeEvents(ctx context.Context, tenantID string) ([]platform.RuntimeEvent, error) {
	return listJSON[platform.RuntimeEvent](ctx, p.db, pgRebind(`SELECT data FROM runtimeevts WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

func (p *Postgres) PutPentest(ctx context.Context, eng pentest.Engagement) error {
	return p.upsertTID(ctx, `INSERT INTO pentests(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, eng.TenantID, eng.ID, eng)
}
func (p *Postgres) ListPentests(ctx context.Context, tenantID string) ([]pentest.Engagement, error) {
	return listJSON[pentest.Engagement](ctx, p.db, pgRebind(`SELECT data FROM pentests WHERE tenant_id=? ORDER BY rowid`), tenantID)
}
func (p *Postgres) GetPentest(ctx context.Context, tenantID, id string) (pentest.Engagement, error) {
	var e pentest.Engagement
	err := p.get(ctx, &e, `SELECT data FROM pentests WHERE tenant_id=? AND id=?`, tenantID, id)
	return e, err
}

func (p *Postgres) PutReviewRequest(ctx context.Context, r platform.ReviewRequest) error {
	return p.upsertTID(ctx, `INSERT INTO reviews(tenant_id,id,data) VALUES(?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET data=excluded.data`, r.TenantID, r.ID, r)
}
func (p *Postgres) ListReviewRequests(ctx context.Context, tenantID string) ([]platform.ReviewRequest, error) {
	return listJSON[platform.ReviewRequest](ctx, p.db, pgRebind(`SELECT data FROM reviews WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

// --- control state (tenant+framework+control) ---

func (p *Postgres) UpsertControlState(ctx context.Context, cs platform.ControlState) error {
	d, err := enc(cs)
	if err != nil {
		return err
	}
	return p.exec(ctx,
		`INSERT INTO controls(tenant_id,framework,control_id,data) VALUES(?,?,?,?)
		 ON CONFLICT(tenant_id,framework,control_id) DO UPDATE SET data=excluded.data`,
		cs.TenantID, cs.Framework, cs.ControlID, d)
}
func (p *Postgres) Posture(ctx context.Context, tenantID, framework string) ([]platform.ControlState, error) {
	return listJSON[platform.ControlState](ctx, p.db, pgRebind(`SELECT data FROM controls WHERE tenant_id=? AND framework=? ORDER BY rowid`), tenantID, framework)
}

// --- third-party apps (replace the whole (tenant,provider) set atomically) ---

func (p *Postgres) ReplaceThirdPartyApps(ctx context.Context, tenantID, provider string, apps []platform.ThirdPartyApp) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, pgRebind(`DELETE FROM apps WHERE tenant_id=? AND provider=?`), tenantID, provider); err != nil {
		return err
	}
	for _, a := range apps {
		d, err := enc(a)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, pgRebind(`INSERT INTO apps(tenant_id,provider,app_id,data) VALUES(?,?,?,?)`), tenantID, provider, a.AppID, d); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (p *Postgres) ListThirdPartyApps(ctx context.Context, tenantID string) ([]platform.ThirdPartyApp, error) {
	return listJSON[platform.ThirdPartyApp](ctx, p.db, pgRebind(`SELECT data FROM apps WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

// --- users & sessions ---

func (p *Postgres) PutUser(ctx context.Context, u platform.User) error {
	d, err := enc(u)
	if err != nil {
		return err
	}
	return p.exec(ctx,
		`INSERT INTO users(id,tenant_id,email,data) VALUES(?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET tenant_id=excluded.tenant_id, email=excluded.email, data=excluded.data`,
		u.ID, u.TenantID, u.Email, d)
}
func (p *Postgres) GetUser(ctx context.Context, id string) (platform.User, error) {
	var u platform.User
	err := p.get(ctx, &u, `SELECT data FROM users WHERE id=?`, id)
	return u, err
}
func (p *Postgres) GetUserByEmail(ctx context.Context, email string) (platform.User, error) {
	var u platform.User
	err := p.get(ctx, &u, `SELECT data FROM users WHERE lower(email)=lower(?) LIMIT 1`, email)
	return u, err
}
func (p *Postgres) ListUsers(ctx context.Context, tenantID string) ([]platform.User, error) {
	return listJSON[platform.User](ctx, p.db, pgRebind(`SELECT data FROM users WHERE tenant_id=? ORDER BY rowid`), tenantID)
}

func (p *Postgres) PutSession(ctx context.Context, sess platform.Session) error {
	d, err := enc(sess)
	if err != nil {
		return err
	}
	return p.exec(ctx, `INSERT INTO sessions(token,data) VALUES(?,?) ON CONFLICT(token) DO UPDATE SET data=excluded.data`, sess.Token, d)
}
func (p *Postgres) GetSession(ctx context.Context, token string) (platform.Session, error) {
	var sess platform.Session
	err := p.get(ctx, &sess, `SELECT data FROM sessions WHERE token=?`, token)
	return sess, err
}
func (p *Postgres) DeleteSession(ctx context.Context, token string) error {
	return p.exec(ctx, `DELETE FROM sessions WHERE token=?`, token)
}

// DeleteSessionsForUser revokes every session for a user. Sessions are a JSON blob keyed by token (no
// user_id column), so scan the small sessions set and delete the matches by token.
func (p *Postgres) DeleteSessionsForUser(ctx context.Context, userID string) error {
	sessions, err := listJSON[platform.Session](ctx, p.db, pgRebind(`SELECT data FROM sessions`))
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if sess.UserID == userID {
			if err := p.exec(ctx, `DELETE FROM sessions WHERE token=?`, sess.Token); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- operators & operator sessions ---

func (p *Postgres) PutOperator(ctx context.Context, o platform.Operator) error {
	d, err := enc(o)
	if err != nil {
		return err
	}
	return p.exec(ctx,
		`INSERT INTO operators(id,email,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET email=excluded.email, data=excluded.data`,
		o.ID, o.Email, d)
}
func (p *Postgres) GetOperator(ctx context.Context, id string) (platform.Operator, error) {
	var o platform.Operator
	err := p.get(ctx, &o, `SELECT data FROM operators WHERE id=?`, id)
	return o, err
}
func (p *Postgres) GetOperatorByEmail(ctx context.Context, email string) (platform.Operator, error) {
	var o platform.Operator
	err := p.get(ctx, &o, `SELECT data FROM operators WHERE lower(email)=lower(?) LIMIT 1`, email)
	return o, err
}
func (p *Postgres) PutOperatorSession(ctx context.Context, sess platform.OperatorSession) error {
	d, err := enc(sess)
	if err != nil {
		return err
	}
	return p.exec(ctx, `INSERT INTO opsessions(token,data) VALUES(?,?) ON CONFLICT(token) DO UPDATE SET data=excluded.data`, sess.Token, d)
}
func (p *Postgres) GetOperatorSession(ctx context.Context, token string) (platform.OperatorSession, error) {
	var sess platform.OperatorSession
	err := p.get(ctx, &sess, `SELECT data FROM opsessions WHERE token=?`, token)
	return sess, err
}
func (p *Postgres) DeleteOperatorSession(ctx context.Context, token string) error {
	return p.exec(ctx, `DELETE FROM opsessions WHERE token=?`, token)
}
