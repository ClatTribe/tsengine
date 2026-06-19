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

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ErrNotFound is returned when a scoped lookup misses (wrong id, or — critically —
// the right id under the wrong tenant).
var ErrNotFound = errors.New("store: not found")

// Open returns the right Store for a path — the single source of truth for store-path
// routing, shared by the platform server and dev tooling so they can't drift:
//
//	""                      → in-memory (ephemeral)
//	*.db / *.sqlite[3]      → durable SQLite (the production single-box backend)
//	any other path (*.json) → the whole-snapshot file store
//
// Callers that want startup logging wrap this; the routing itself lives here.
func Open(path string) (Store, error) {
	if path == "" {
		return NewMemory(), nil
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

	// --- GRC system-of-record ---
	UpsertControlState(ctx context.Context, cs platform.ControlState) error
	Posture(ctx context.Context, tenantID, framework string) ([]platform.ControlState, error)

	// --- incidents (the continuous-monitoring system-of-record) ---
	PutIncident(ctx context.Context, i platform.Incident) error
	ListIncidents(ctx context.Context, tenantID string) ([]platform.Incident, error)

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
}
