// Package store is the multi-tenant persistence layer for the platform — the
// system-of-record (docs/autonomous-team.md §3.1). Every call is scoped to a
// tenantID and the store MUST NOT return one tenant's data to another; that
// isolation is the security boundary of the whole product.
//
// This file defines the Store interface. memory.go provides an in-memory
// implementation used for tests and the MVP; a sqlite/Postgres implementation
// (adding a tenant_id column + row scoping, reusing the findingstore lifecycle
// logic) lands in Phase 1 behind the same interface.
package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ErrNotFound is returned when a scoped lookup misses (wrong id, or — critically —
// the right id under the wrong tenant).
var ErrNotFound = errors.New("store: not found")

// Open returns the right Store for a path — the single source of truth for store-path
// routing, shared by the platform server and dev tooling so they can't drift:
//
//	""                          → in-memory (ephemeral)
//	postgres:// | postgresql:// → durable Postgres (Supabase / RDS / Neon — multi-node scale-out)
//	*.db / *.sqlite[3]          → durable SQLite (the production single-box backend)
//	any other path (*.json)     → the whole-snapshot file store
//
// Callers that want startup logging wrap this; the routing itself lives here.
func Open(path string) (Store, error) {
	if path == "" {
		return NewMemory(), nil
	}
	if strings.HasPrefix(path, "postgres://") || strings.HasPrefix(path, "postgresql://") {
		return OpenPostgres(path)
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".db", ".sqlite", ".sqlite3":
		return OpenSQLite(path)
	default:
		return OpenFile(path)
	}
}

// FindingFilter narrows a finding list. Zero value = all of the tenant's findings.
type FindingFilter struct {
	AssetID  string
	Severity types.Severity
	Status   string // verification_status
}

// Store is the tenant-scoped system-of-record. Implementations must enforce that a
// tenantID only ever sees its own rows.
type Store interface {
	// --- tenancy ---
	PutTenant(ctx context.Context, t platform.Tenant) error
	GetTenant(ctx context.Context, id string) (platform.Tenant, error)
	ListTenants(ctx context.Context) ([]platform.Tenant, error)

	// --- connections / assets / engagements ---
	PutConnection(ctx context.Context, c platform.Connection) error
	ListConnections(ctx context.Context, tenantID string) ([]platform.Connection, error)
	// DeleteConnection removes a tenant's connection by id (no-op if absent). Tenant-scoped:
	// it only ever touches the given tenant's connections.
	DeleteConnection(ctx context.Context, tenantID, id string) error
	PutAsset(ctx context.Context, a platform.Asset) error
	ListAssets(ctx context.Context, tenantID string) ([]platform.Asset, error)
	PutEngagement(ctx context.Context, e platform.Engagement) error
	ListEngagements(ctx context.Context, tenantID string) ([]platform.Engagement, error)

	// --- findings (the engine's output, persisted per tenant) ---
	PutFinding(ctx context.Context, tenantID string, f types.Finding) error
	ListFindings(ctx context.Context, tenantID string, filter FindingFilter) ([]types.Finding, error)

	// --- remediation actions + the HITL queue ---
	PutAction(ctx context.Context, a platform.Action) error
	GetAction(ctx context.Context, tenantID, id string) (platform.Action, error)
	PendingApprovals(ctx context.Context, tenantID string) ([]platform.Action, error)
	// ListActions returns ALL of a tenant's actions (any status) — used by the activity view and
	// by fix-verification (which re-tests APPLIED actions). Tenant-scoped like every other list.
	ListActions(ctx context.Context, tenantID string) ([]platform.Action, error)

	// --- GRC system-of-record ---
	UpsertControlState(ctx context.Context, cs platform.ControlState) error
	Posture(ctx context.Context, tenantID, framework string) ([]platform.ControlState, error)

	// --- incidents (the continuous-monitoring system-of-record) ---
	PutIncident(ctx context.Context, i platform.Incident) error
	ListIncidents(ctx context.Context, tenantID string) ([]platform.Incident, error)

	// --- risk register (the vCISO judgment artifact; treatment decisions are HITL) ---
	PutRisk(ctx context.Context, r platform.Risk) error
	ListRisks(ctx context.Context, tenantID string) ([]platform.Risk, error)

	// --- persisted AI Security Engineer analyses (Triage / Investigate / Cloud) — so a run survives
	// navigation; the deterministic id overwrites the prior analysis for the same scope (latest wins) ---
	PutAIAnalysis(ctx context.Context, a platform.AIAnalysis) error
	ListAIAnalyses(ctx context.Context, tenantID string) ([]platform.AIAnalysis, error)

	// --- continuous-compliance evidence timeline (APPEND-ONLY per-framework posture snapshots, so an
	// auditor sees a control held across the audit window, not just now). List returns all of a tenant's
	// snapshots (any framework) oldest-first; callers filter by framework. ---
	PutComplianceSnapshot(ctx context.Context, s platform.ComplianceSnapshot) error
	ListComplianceSnapshots(ctx context.Context, tenantID string) ([]platform.ComplianceSnapshot, error)

	// --- audit engagements (external-auditor attestation; the legal layer) ---
	PutAuditEngagement(ctx context.Context, e platform.AuditEngagement) error
	ListAuditEngagements(ctx context.Context, tenantID string) ([]platform.AuditEngagement, error)

	// --- security-program policies (vCISO program; publish/acknowledge are HITL) ---
	PutPolicy(ctx context.Context, p platform.Policy) error
	ListPolicies(ctx context.Context, tenantID string) ([]platform.Policy, error)

	// --- issue suppression (ignore / accept-risk), keyed by issue dedup key ---
	PutIgnoreRule(ctx context.Context, ir platform.IgnoreRule) error
	ListIgnoreRules(ctx context.Context, tenantID string) ([]platform.IgnoreRule, error)
	DeleteIgnoreRule(ctx context.Context, tenantID, issueKey string) error

	// --- custom exclusion rules (pattern-based noise filter), keyed by rule id ---
	PutExclusionRule(ctx context.Context, er platform.ExclusionRule) error
	ListExclusionRules(ctx context.Context, tenantID string) ([]platform.ExclusionRule, error)
	DeleteExclusionRule(ctx context.Context, tenantID, id string) error

	// --- runtime-protection events (in-app firewall / RASP signal; append-only) ---
	PutRuntimeEvent(ctx context.Context, ev platform.RuntimeEvent) error
	ListRuntimeEvents(ctx context.Context, tenantID string) ([]platform.RuntimeEvent, error)

	// --- pentest engagements (the productized AI-pentest lifecycle) ---
	PutPentest(ctx context.Context, eng pentest.Engagement) error
	ListPentests(ctx context.Context, tenantID string) ([]pentest.Engagement, error)
	GetPentest(ctx context.Context, tenantID, id string) (pentest.Engagement, error)

	// --- human-expert review requests (the AI + human escalation) ---
	PutReviewRequest(ctx context.Context, r platform.ReviewRequest) error
	ListReviewRequests(ctx context.Context, tenantID string) ([]platform.ReviewRequest, error)

	// --- third-party app inventory (refreshed per operate scan, per provider) ---
	ReplaceThirdPartyApps(ctx context.Context, tenantID, provider string, apps []platform.ThirdPartyApp) error
	ListThirdPartyApps(ctx context.Context, tenantID string) ([]platform.ThirdPartyApp, error)

	// --- users & sessions (real account auth) ---
	PutUser(ctx context.Context, u platform.User) error
	GetUser(ctx context.Context, id string) (platform.User, error)
	GetUserByEmail(ctx context.Context, email string) (platform.User, error)
	ListUsers(ctx context.Context, tenantID string) ([]platform.User, error)
	PutSession(ctx context.Context, s platform.Session) error
	GetSession(ctx context.Context, token string) (platform.Session, error)
	DeleteSession(ctx context.Context, token string) error
	// DeleteSessionsForUser revokes EVERY session belonging to a user — the kill-stolen-tokens step on
	// a credential change/reset, so a captured session can't outlive the password it was issued under.
	DeleteSessionsForUser(ctx context.Context, userID string) error

	// --- operators (cross-tenant practitioner identities; a SEPARATE namespace from tenant users) ---
	PutOperator(ctx context.Context, o platform.Operator) error
	GetOperatorByEmail(ctx context.Context, email string) (platform.Operator, error)
	GetOperator(ctx context.Context, id string) (platform.Operator, error)
	PutOperatorSession(ctx context.Context, s platform.OperatorSession) error
	GetOperatorSession(ctx context.Context, token string) (platform.OperatorSession, error)
	DeleteOperatorSession(ctx context.Context, token string) error
}
