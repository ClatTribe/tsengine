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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Snapshot is a tenant's latest cloud inventory (the cloudgraph.ParseInventory input) plus the prowler
// findings it was assessed with — everything cloudagent needs to reconstruct its graph.
type Snapshot struct {
	TenantID string `json:"tenant_id"`
	// Account names the cloud account this snapshot describes ("aws:123456789012", "gcp:acme-prod").
	// Derived from the inventory when a caller leaves it empty. It is the storage KEY: a tenant with an
	// AWS account and a GCP project holds two snapshots, not one that each overwrites.
	Account    string          `json:"account,omitempty"`
	Inventory  json.RawMessage `json:"inventory"`
	Prowler    []types.Finding `json:"prowler,omitempty"`
	CapturedAt time.Time       `json:"captured_at"`
	// CoverageGaps records what this snapshot could NOT answer, keyed by the concern
	// (e.g. "privilege-escalation"), with the reason and the field to populate.
	//
	// It is stored rather than only returned at ingest because the person who needs it is
	// not the one who posted the snapshot. A CI job posts the inventory and reads the
	// response; a human opens the attack-path page days later and sees no escalation
	// paths. Without this the caveat reached only the caller, and the reader — the one
	// making a decision — got silence that looks exactly like a clean account.
	CoverageGaps map[string]string `json:"coverage_gaps,omitempty"`
	// GitHubTrusts are the repository → role transitions the account's trust policies state: which
	// GitHub repository's workflows may assume which role via OIDC, with no stored credential. Derived
	// at ingest from the raw trust documents (which the built inventory does not keep) and stored so
	// the estate graph can draw code → cloud on every read, not only at the moment of ingest.
	GitHubTrusts []GitHubTrust `json:"github_trusts,omitempty"`
}

// GitHubTrust mirrors estateingest.GitHubOIDCTrust without importing it (cloudsnap stays a leaf).
type GitHubTrust struct {
	Repository string   `json:"repository"` // "owner/name"
	RoleARN    string   `json:"role_arn"`
	RoleName   string   `json:"role_name,omitempty"`
	Privileged bool     `json:"privileged"`
	Evidence   []string `json:"evidence"`
	Why        string   `json:"why,omitempty"`
}

// Store persists the latest cloud snapshot per tenant (latest-wins). Get returns ok=false when the
// tenant has none — never another tenant's.
//
// ONE SNAPSHOT PER CLOUD ACCOUNT, NOT PER TENANT. It used to be one per tenant, latest-wins, so a tenant
// with both an AWS account and a GCP project had each ingest overwrite the other: the attack-path page
// showed whichever cloud was posted last, and every ingest diffed one cloud against the OTHER, so drift
// reported the entire account as newly created — a flood of false "resource became public" findings on
// every pass once both clouds synced on a schedule.
//
// Get returns the MERGED view across the tenant's accounts (one account → that snapshot unchanged), so
// the readers that reason over "the tenant's cloud" — the AI cloud engineer, the estate graph, the
// coverage banner — see every cloud. GetAccount returns one account's own snapshot, which is what a
// drift diff must compare against.
type Store interface {
	Put(ctx context.Context, snap Snapshot) error
	Get(ctx context.Context, tenantID string) (Snapshot, bool, error)
	GetAccount(ctx context.Context, tenantID, account string) (Snapshot, bool, error)
}

// AccountOf derives the account key from an inventory's own provider and account_id fields. An AWS
// inventory that predates the provider field reads as AWS (the only provider that existed then).
func AccountOf(inventory json.RawMessage) string {
	var head struct {
		Provider  string `json:"provider"`
		AccountID string `json:"account_id"`
	}
	if len(inventory) == 0 || json.Unmarshal(inventory, &head) != nil {
		return ""
	}
	prov := strings.ToLower(strings.TrimSpace(head.Provider))
	if prov == "" {
		prov = "aws"
	}
	if head.AccountID == "" {
		return prov
	}
	return prov + ":" + strings.TrimSpace(head.AccountID)
}

func normalise(snap Snapshot) Snapshot {
	if snap.Account == "" {
		snap.Account = AccountOf(snap.Inventory)
	}
	return snap
}

// Merge combines one tenant's per-account snapshots into the single view readers expect. Arrays in the
// inventories are concatenated (resource ids are provider-native — ARNs, service-account emails,
// resource paths — so they do not collide across clouds), coverage notes are prefixed with the account
// they describe so a gap is attributed to the cloud it belongs to, and the result names every account.
func Merge(snaps []Snapshot) (Snapshot, bool) {
	switch len(snaps) {
	case 0:
		return Snapshot{}, false
	case 1:
		return snaps[0], true
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Account < snaps[j].Account })
	out := Snapshot{TenantID: snaps[0].TenantID, CoverageGaps: map[string]string{}}
	merged := map[string]json.RawMessage{}
	var accounts, providers []string
	for _, sn := range snaps {
		accounts = append(accounts, sn.Account)
		if sn.CapturedAt.After(out.CapturedAt) {
			out.CapturedAt = sn.CapturedAt
		}
		out.Prowler = append(out.Prowler, sn.Prowler...)
		out.GitHubTrusts = append(out.GitHubTrusts, sn.GitHubTrusts...)
		for k, v := range sn.CoverageGaps {
			out.CoverageGaps[sn.Account+": "+k] = v
		}
		var inv map[string]json.RawMessage
		if json.Unmarshal(sn.Inventory, &inv) != nil {
			continue
		}
		if p, ok := inv["provider"]; ok {
			var ps string
			_ = json.Unmarshal(p, &ps)
			providers = append(providers, ps)
		}
		for k, v := range inv {
			var arr []json.RawMessage
			if json.Unmarshal(v, &arr) != nil {
				continue // scalars are replaced below
			}
			var prev []json.RawMessage
			if pv, ok := merged[k]; ok {
				_ = json.Unmarshal(pv, &prev)
			}
			b, _ := json.Marshal(append(prev, arr...))
			merged[k] = b
		}
	}
	prov := "multi"
	if len(providers) > 0 && allSame(providers) {
		prov = providers[0]
	}
	merged["provider"], _ = json.Marshal(prov)
	merged["account_id"], _ = json.Marshal(strings.Join(accounts, "+"))
	merged["captured_at"], _ = json.Marshal(out.CapturedAt)
	out.Inventory, _ = json.Marshal(merged)
	out.Account = strings.Join(accounts, "+")
	if len(out.CoverageGaps) == 0 {
		out.CoverageGaps = nil
	}
	return out, true
}

func allSame(xs []string) bool {
	for _, x := range xs {
		if x != xs[0] {
			return false
		}
	}
	return true
}

var errNoTenant = errors.New("cloudsnap: empty tenant id")

// MemStore is an in-process Store (lost on restart) — the test + no-config-durability default.
type MemStore struct {
	mu   sync.RWMutex
	snap map[string]map[string]Snapshot // tenant → account → snapshot
}

// NewMemStore returns an empty in-process store.
func NewMemStore() *MemStore { return &MemStore{snap: map[string]map[string]Snapshot{}} }

// Put stores (latest-wins) the snapshot for its tenant and account.
func (m *MemStore) Put(_ context.Context, snap Snapshot) error {
	if snap.TenantID == "" {
		return errNoTenant
	}
	snap = normalise(snap)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.snap[snap.TenantID] == nil {
		m.snap[snap.TenantID] = map[string]Snapshot{}
	}
	m.snap[snap.TenantID][snap.Account] = snap
	return nil
}

// Get returns the tenant's merged view across accounts, ok=false if none.
func (m *MemStore) Get(_ context.Context, tenantID string) (Snapshot, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []Snapshot
	for _, sn := range m.snap[tenantID] {
		all = append(all, sn)
	}
	s, ok := Merge(all)
	return s, ok, nil
}

// GetAccount returns one account's snapshot.
func (m *MemStore) GetAccount(_ context.Context, tenantID, account string) (Snapshot, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.snap[tenantID][account]
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

// accountPath is the per-(tenant, account) file. The original one-file-per-tenant name
// (path(tenantID)) is still READ, as the snapshot written before accounts were keyed.
func (f *FileStore) accountPath(tenantID, account string) string {
	return filepath.Join(f.dir, safeName(tenantID)+"--"+safeName(account)+".json")
}

// Put writes the snapshot atomically (temp + rename). A legacy per-tenant file describing the SAME
// account is removed, so the account is not merged in twice.
func (f *FileStore) Put(_ context.Context, snap Snapshot) error {
	if snap.TenantID == "" {
		return errNoTenant
	}
	snap = normalise(snap)
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	dst := f.accountPath(snap.TenantID, snap.Account)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	if legacy, ok, _ := f.readFile(f.path(snap.TenantID)); ok && normalise(legacy).Account == snap.Account {
		_ = os.Remove(f.path(snap.TenantID))
	}
	return nil
}

func (f *FileStore) readFile(path string) (Snapshot, bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is sanitised + dir-scoped
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
	return normalise(s), true, nil
}

// all reads every snapshot of a tenant: the per-account files and a legacy per-tenant one.
func (f *FileStore) all(tenantID string) ([]Snapshot, error) {
	var out []Snapshot
	if s, ok, err := f.readFile(f.path(tenantID)); err != nil {
		return nil, err
	} else if ok {
		out = append(out, s)
	}
	matches, err := filepath.Glob(filepath.Join(f.dir, safeName(tenantID)+"--*.json"))
	if err != nil {
		return nil, err
	}
	for _, m := range matches {
		s, ok, err := f.readFile(m)
		if err != nil {
			return nil, err
		}
		if ok && s.TenantID == tenantID {
			out = append(out, s)
		}
	}
	return out, nil
}

// Get reads the tenant's merged view, ok=false if it has no snapshot.
func (f *FileStore) Get(_ context.Context, tenantID string) (Snapshot, bool, error) {
	all, err := f.all(tenantID)
	if err != nil {
		return Snapshot{}, false, err
	}
	s, ok := Merge(all)
	return s, ok, nil
}

// GetAccount reads one account's snapshot, falling back to a legacy per-tenant file that describes
// that account — so the first sync after an upgrade diffs against the real baseline instead of
// reporting the whole account as new.
func (f *FileStore) GetAccount(_ context.Context, tenantID, account string) (Snapshot, bool, error) {
	if s, ok, err := f.readFile(f.accountPath(tenantID, account)); err != nil || ok {
		return s, ok, err
	}
	if s, ok, err := f.readFile(f.path(tenantID)); err == nil && ok && s.Account == account {
		return s, true, nil
	}
	return Snapshot{}, false, nil
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
