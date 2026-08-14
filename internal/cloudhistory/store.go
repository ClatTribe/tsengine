package cloudhistory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// DefaultRetain caps how many captures a tenant's timeline keeps.
//
// A cap is not optional. An uncapped append-only store on a per-scan cadence grows without bound, and
// the failure mode is the worst kind — it works fine in every test and fills a disk in production
// months later. 200 captures is roughly a year at daily change, and change detection means an estate
// that is not moving consumes no rows at all.
const DefaultRetain = 200

var errNoTenant = errors.New("cloudhistory: empty tenant id")

// Store is the append-only timeline. Append is a no-op when nothing security-relevant changed, so the
// history records CHANGES rather than scans.
type Store interface {
	// Append records the digest unless it matches the tenant's most recent one. Returns whether it was
	// recorded, so a caller can log "estate unchanged" honestly instead of implying a capture happened.
	Append(ctx context.Context, d Digest) (recorded bool, err error)
	// Timeline returns the tenant's captures, OLDEST FIRST (the order Diff and WhenChanged expect).
	Timeline(ctx context.Context, tenantID string) ([]Digest, error)
}

// MemStore is an in-process timeline (lost on restart) — the test + no-config default.
type MemStore struct {
	mu     sync.RWMutex
	byTen  map[string][]Digest
	Retain int
}

func NewMemStore() *MemStore { return &MemStore{byTen: map[string][]Digest{}, Retain: DefaultRetain} }

func (m *MemStore) Append(_ context.Context, d Digest) (bool, error) {
	if d.TenantID == "" {
		return false, errNoTenant
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	hist := m.byTen[d.TenantID]
	if n := len(hist); n > 0 && hist[n-1].Equal(d) {
		return false, nil // unchanged estate → no row; the timeline stays a record of change
	}
	hist = append(hist, d)
	m.byTen[d.TenantID] = trim(hist, m.Retain)
	return true, nil
}

func (m *MemStore) Timeline(_ context.Context, tenantID string) ([]Digest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Digest, len(m.byTen[tenantID]))
	copy(out, m.byTen[tenantID])
	return out, nil
}

// FileStore persists one JSON timeline per tenant. Same atomic-write discipline as cloudsnap: write a
// temp file and rename, so a crash mid-write cannot leave a truncated history.
type FileStore struct {
	dir    string
	mu     sync.Mutex
	Retain int
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir, Retain: DefaultRetain}, nil
}

func (f *FileStore) path(tenantID string) string {
	// The tenant id is a generated hex string, but a path is a path: refuse anything that could escape.
	safe := filepath.Base(filepath.Clean(tenantID))
	return filepath.Join(f.dir, safe+".history.json")
}

func (f *FileStore) Append(ctx context.Context, d Digest) (bool, error) {
	if d.TenantID == "" {
		return false, errNoTenant
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	hist, err := f.read(d.TenantID)
	if err != nil {
		return false, err
	}
	if n := len(hist); n > 0 && hist[n-1].Equal(d) {
		return false, nil
	}
	hist = trim(append(hist, d), f.Retain)
	b, err := json.Marshal(hist)
	if err != nil {
		return false, err
	}
	tmp := f.path(d.TenantID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, f.path(d.TenantID)); err != nil {
		return false, err
	}
	return true, nil
}

func (f *FileStore) Timeline(_ context.Context, tenantID string) ([]Digest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.read(tenantID)
}

func (f *FileStore) read(tenantID string) ([]Digest, error) {
	b, err := os.ReadFile(f.path(tenantID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // no history yet is not an error
	}
	if err != nil {
		return nil, err
	}
	var hist []Digest
	if err := json.Unmarshal(b, &hist); err != nil {
		return nil, err
	}
	sort.SliceStable(hist, func(i, j int) bool { return hist[i].CapturedAt.Before(hist[j].CapturedAt) })
	return hist, nil
}

// trim keeps the newest `retain` captures. It drops from the FRONT: the oldest state is the least useful
// (nobody asks what an estate looked like a year ago as often as they ask what changed last week), and
// keeping the newest means the drift baseline is always present.
func trim(hist []Digest, retain int) []Digest {
	if retain <= 0 || len(hist) <= retain {
		return hist
	}
	return append([]Digest(nil), hist[len(hist)-retain:]...)
}
