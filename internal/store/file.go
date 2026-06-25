package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// File is a dependency-free, JSON-file-backed Store for single-node deployments. It
// embeds Memory (so all read/query methods + isolation logic are reused unchanged) and
// overrides the mutating methods to snapshot the whole store to disk atomically after
// each write. Good enough for the MVP — a sqlite/Postgres Store replaces it behind the
// same interface when concurrency/scale demand it.
//
// Persistence is synchronous + whole-snapshot: simple and crash-safe (temp file +
// rename), at the cost of write throughput. The platform's write rate (scans, the
// occasional approval) is low enough that this is fine.
type File struct {
	*Memory
	path string
	mu   sync.Mutex // serializes disk writes (the embedded Memory guards in-memory state)
}

// OpenFile loads a File store from path, creating an empty one if the file is absent.
func OpenFile(path string) (*File, error) {
	f := &File{Memory: NewMemory(), path: path}
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil // fresh store
		}
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("store: decode %s: %w", path, err)
	}
	f.Memory.load(snap)
	return f, nil
}

// persist writes the current snapshot to disk atomically (temp + rename).
func (f *File) persist() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := json.MarshalIndent(f.Memory.Export(), "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(f.path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// --- mutating methods: delegate to Memory, then persist. Read methods are promoted
// from the embedded *Memory unchanged. ---

func (f *File) PutTenant(ctx context.Context, t platform.Tenant) error {
	if err := f.Memory.PutTenant(ctx, t); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutConnection(ctx context.Context, c platform.Connection) error {
	if err := f.Memory.PutConnection(ctx, c); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutAsset(ctx context.Context, a platform.Asset) error {
	if err := f.Memory.PutAsset(ctx, a); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutEngagement(ctx context.Context, e platform.Engagement) error {
	if err := f.Memory.PutEngagement(ctx, e); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutFinding(ctx context.Context, tenantID string, fn types.Finding) error {
	if err := f.Memory.PutFinding(ctx, tenantID, fn); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutAction(ctx context.Context, a platform.Action) error {
	if err := f.Memory.PutAction(ctx, a); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) UpsertControlState(ctx context.Context, cs platform.ControlState) error {
	if err := f.Memory.UpsertControlState(ctx, cs); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutIncident(ctx context.Context, i platform.Incident) error {
	if err := f.Memory.PutIncident(ctx, i); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutRisk(ctx context.Context, r platform.Risk) error {
	if err := f.Memory.PutRisk(ctx, r); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutAuditEngagement(ctx context.Context, e platform.AuditEngagement) error {
	if err := f.Memory.PutAuditEngagement(ctx, e); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutPolicy(ctx context.Context, p platform.Policy) error {
	if err := f.Memory.PutPolicy(ctx, p); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutIgnoreRule(ctx context.Context, ir platform.IgnoreRule) error {
	if err := f.Memory.PutIgnoreRule(ctx, ir); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) DeleteIgnoreRule(ctx context.Context, tenantID, issueKey string) error {
	if err := f.Memory.DeleteIgnoreRule(ctx, tenantID, issueKey); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutExclusionRule(ctx context.Context, er platform.ExclusionRule) error {
	if err := f.Memory.PutExclusionRule(ctx, er); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) DeleteExclusionRule(ctx context.Context, tenantID, id string) error {
	if err := f.Memory.DeleteExclusionRule(ctx, tenantID, id); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutRuntimeEvent(ctx context.Context, ev platform.RuntimeEvent) error {
	if err := f.Memory.PutRuntimeEvent(ctx, ev); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutPentest(ctx context.Context, eng pentest.Engagement) error {
	if err := f.Memory.PutPentest(ctx, eng); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutReviewRequest(ctx context.Context, r platform.ReviewRequest) error {
	if err := f.Memory.PutReviewRequest(ctx, r); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutUser(ctx context.Context, u platform.User) error {
	if err := f.Memory.PutUser(ctx, u); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutSession(ctx context.Context, s platform.Session) error {
	if err := f.Memory.PutSession(ctx, s); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) DeleteSession(ctx context.Context, token string) error {
	if err := f.Memory.DeleteSession(ctx, token); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutOperator(ctx context.Context, o platform.Operator) error {
	if err := f.Memory.PutOperator(ctx, o); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) PutOperatorSession(ctx context.Context, s platform.OperatorSession) error {
	if err := f.Memory.PutOperatorSession(ctx, s); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) DeleteOperatorSession(ctx context.Context, token string) error {
	if err := f.Memory.DeleteOperatorSession(ctx, token); err != nil {
		return err
	}
	return f.persist()
}

func (f *File) ReplaceThirdPartyApps(ctx context.Context, tenantID, provider string, apps []platform.ThirdPartyApp) error {
	if err := f.Memory.ReplaceThirdPartyApps(ctx, tenantID, provider, apps); err != nil {
		return err
	}
	return f.persist()
}
