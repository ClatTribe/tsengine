package store

import (
	"context"
	"sync"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Memory is an in-memory, mutex-guarded Store for tests and the MVP. Tenant
// isolation is enforced by keying every collection on tenantID and never crossing
// it. A persistent (sqlite/Postgres) Store replaces this behind the same interface.
type Memory struct {
	mu sync.RWMutex

	tenants     map[string]platform.Tenant
	connections map[string][]platform.Connection            // tenantID → connections
	assets      map[string][]platform.Asset                 // tenantID → assets
	engagements map[string][]platform.Engagement            // tenantID → engagements
	findings    map[string][]types.Finding                  // tenantID → findings
	actions     map[string]map[string]platform.Action       // tenantID → actionID → action
	controls    map[string]map[string]platform.ControlState // tenantID → "framework/control" → state
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		tenants:     map[string]platform.Tenant{},
		connections: map[string][]platform.Connection{},
		assets:      map[string][]platform.Asset{},
		engagements: map[string][]platform.Engagement{},
		findings:    map[string][]types.Finding{},
		actions:     map[string]map[string]platform.Action{},
		controls:    map[string]map[string]platform.ControlState{},
	}
}

func (m *Memory) PutTenant(_ context.Context, t platform.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenants[t.ID] = t
	return nil
}

func (m *Memory) GetTenant(_ context.Context, id string) (platform.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[id]
	if !ok {
		return platform.Tenant{}, ErrNotFound
	}
	return t, nil
}

func (m *Memory) PutConnection(_ context.Context, c platform.Connection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connections[c.TenantID] = upsertByID(m.connections[c.TenantID], c, func(x platform.Connection) string { return x.ID })
	return nil
}

func (m *Memory) ListConnections(_ context.Context, tenantID string) ([]platform.Connection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clone(m.connections[tenantID]), nil
}

func (m *Memory) PutAsset(_ context.Context, a platform.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assets[a.TenantID] = upsertByID(m.assets[a.TenantID], a, func(x platform.Asset) string { return x.ID })
	return nil
}

func (m *Memory) ListAssets(_ context.Context, tenantID string) ([]platform.Asset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clone(m.assets[tenantID]), nil
}

func (m *Memory) PutEngagement(_ context.Context, e platform.Engagement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.engagements[e.TenantID] = upsertByID(m.engagements[e.TenantID], e, func(x platform.Engagement) string { return x.ID })
	return nil
}

func (m *Memory) ListEngagements(_ context.Context, tenantID string) ([]platform.Engagement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clone(m.engagements[tenantID]), nil
}

func (m *Memory) PutFinding(_ context.Context, tenantID string, f types.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings[tenantID] = upsertByID(m.findings[tenantID], f, func(x types.Finding) string { return x.ID })
	return nil
}

func (m *Memory) ListFindings(_ context.Context, tenantID string, filter FindingFilter) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []types.Finding
	for _, f := range m.findings[tenantID] {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if filter.Status != "" && string(f.VerificationStatus) != filter.Status {
			continue
		}
		// AssetID filter is best-effort: engine findings don't carry it yet, so an
		// AssetID filter with no match returns nothing rather than silently ignoring.
		if filter.AssetID != "" {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func (m *Memory) PutAction(_ context.Context, a platform.Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.actions[a.TenantID] == nil {
		m.actions[a.TenantID] = map[string]platform.Action{}
	}
	m.actions[a.TenantID][a.ID] = a
	return nil
}

func (m *Memory) GetAction(_ context.Context, tenantID, id string) (platform.Action, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.actions[tenantID][id]
	if !ok {
		return platform.Action{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) PendingApprovals(_ context.Context, tenantID string) ([]platform.Action, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []platform.Action
	for _, a := range m.actions[tenantID] {
		if a.Status == platform.ActPendingApproval {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *Memory) UpsertControlState(_ context.Context, cs platform.ControlState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.controls[cs.TenantID] == nil {
		m.controls[cs.TenantID] = map[string]platform.ControlState{}
	}
	m.controls[cs.TenantID][cs.Framework+"/"+cs.ControlID] = cs
	return nil
}

func (m *Memory) Posture(_ context.Context, tenantID, framework string) ([]platform.ControlState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []platform.ControlState
	for _, cs := range m.controls[tenantID] {
		if cs.Framework == framework {
			out = append(out, cs)
		}
	}
	return out, nil
}

// upsertByID replaces an element with the same id, or appends it.
func upsertByID[T any](xs []T, v T, id func(T) string) []T {
	for i := range xs {
		if id(xs[i]) == id(v) {
			xs[i] = v
			return xs
		}
	}
	return append(xs, v)
}

func clone[T any](xs []T) []T {
	if xs == nil {
		return nil
	}
	out := make([]T, len(xs))
	copy(out, xs)
	return out
}
