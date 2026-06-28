// Package cloudsnap persists a tenant's most-recent cloud inventory snapshot so the AI cloud engineer
// (cloudagent) can reason over STORED cloud state, not only a freshly-POSTED inventory. This is the
// prerequisite for the L2 generalist delegating cloud-depth to the cloud specialist (the framework's
// "altitude split"): the generalist asks "investigate the cloud", a closure loads the stored snapshot
// and runs cloudagent over it.
//
// It is a FOCUSED store, deliberately separate from the JSON-row domain Store (internal/store): a cloud
// inventory is a large, ephemeral, latest-wins-per-tenant blob, not a domain entity — so it doesn't
// belong in the conformance-tested entity store. Tenant isolation is still the boundary (§18.2 inv. 2):
// a Get for one tenant never returns another's.
package cloudsnap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Snapshot is a tenant's latest cloud inventory (the cloudgraph.ParseInventory input) plus the prowler
// findings it was assessed with — everything cloudagent needs to reconstruct its graph.
type Snapshot struct {
	TenantID   string          `json:"tenant_id"`
	Inventory  json.RawMessage `json:"inventory"`
	Prowler    []types.Finding `json:"prowler,omitempty"`
	CapturedAt time.Time       `json:"captured_at"`
}

// Store persists the latest cloud snapshot per tenant (latest-wins). Get returns ok=false when the
// tenant has none — never another tenant's.
type Store interface {
	Put(ctx context.Context, snap Snapshot) error
	Get(ctx context.Context, tenantID string) (Snapshot, bool, error)
}

var errNoTenant = errors.New("cloudsnap: empty tenant id")

// MemStore is an in-process Store (lost on restart) — the test + no-config-durability default.
type MemStore struct {
	mu   sync.RWMutex
	snap map[string]Snapshot
}

// NewMemStore returns an empty in-process store.
func NewMemStore() *MemStore { return &MemStore{snap: map[string]Snapshot{}} }

// Put stores (latest-wins) the snapshot for snap.TenantID.
func (m *MemStore) Put(_ context.Context, snap Snapshot) error {
	if snap.TenantID == "" {
		return errNoTenant
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snap[snap.TenantID] = snap
	return nil
}

// Get returns the tenant's latest snapshot, ok=false if none.
func (m *MemStore) Get(_ context.Context, tenantID string) (Snapshot, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.snap[tenantID]
	return s, ok, nil
}

// FileStore persists one JSON file per tenant under dir (durable across restarts on a single box).
type FileStore struct {
	dir string
	mu  sync.Mutex // serializes the atomic temp+rename writes
}

// NewFileStore creates (mkdir -p) the directory and returns a durable store.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

// path is the per-tenant file. The tenant id is sanitised against path traversal (it's a
// platform-generated id, but never trust an id used as a filename).
func (f *FileStore) path(tenantID string) string {
	return filepath.Join(f.dir, safeName(tenantID)+".json")
}

// Put writes the snapshot atomically (temp + rename).
func (f *FileStore) Put(_ context.Context, snap Snapshot) error {
	if snap.TenantID == "" {
		return errNoTenant
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tmp := f.path(snap.TenantID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path(snap.TenantID))
}

// Get reads the tenant's snapshot, ok=false if the file doesn't exist.
func (f *FileStore) Get(_ context.Context, tenantID string) (Snapshot, bool, error) {
	data, err := os.ReadFile(f.path(tenantID)) //nolint:gosec // path is sanitised + dir-scoped
	if os.IsNotExist(err) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, err
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}, false, err
	}
	return s, true, nil
}

// safeName maps a tenant id to a filename-safe token (defence-in-depth against path traversal).
func safeName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "_"
	}
	return string(out)
}
