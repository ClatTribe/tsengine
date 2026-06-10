package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Fetcher pulls a live operate.Workspace using an access token (satisfied by
// *operate.GWorkspace). It never holds credentials — the token is resolved per call.
type Fetcher interface {
	Fetch(ctx context.Context, token string, now time.Time) (operate.Workspace, error)
}

// LiveWorkspaceSource is a WorkspaceSource that fetches the snapshot live from the
// asset's connected provider: it finds the asset's Connection, resolves the vaulted
// token, and calls the Fetcher. This is the production path behind the WorkspaceSource
// seam (SnapshotSource is the file-based MVP).
type LiveWorkspaceSource struct {
	Store   store.Store
	Tokens  Tokens
	Fetcher Fetcher
}

// Workspace resolves the asset's connection token and fetches the live workspace.
func (l *LiveWorkspaceSource) Workspace(ctx context.Context, a platform.Asset) (operate.Workspace, error) {
	if l.Fetcher == nil {
		return operate.Workspace{}, fmt.Errorf("operate: no live fetcher configured")
	}
	conns, err := l.Store.ListConnections(ctx, a.TenantID)
	if err != nil {
		return operate.Workspace{}, err
	}
	for _, c := range conns {
		if c.ID != a.ConnectionID {
			continue
		}
		tok, terr := l.Tokens.Resolve(ctx, c)
		if terr != nil {
			return operate.Workspace{}, fmt.Errorf("operate: resolve token: %w", terr)
		}
		return l.Fetcher.Fetch(ctx, tok, time.Time{})
	}
	return operate.Workspace{}, fmt.Errorf("operate: no connection %s for workspace asset %s", a.ConnectionID, a.Target)
}

// CompositeSource prefers a snapshot file (asset Meta[SnapshotKey]) when present, else
// falls back to the live source — so an operator can run on an exported snapshot OR a
// live connection with no config change.
type CompositeSource struct {
	Snapshot WorkspaceSource
	Live     WorkspaceSource
}

// Workspace routes to the snapshot source when the asset names one, else the live source.
func (c CompositeSource) Workspace(ctx context.Context, a platform.Asset) (operate.Workspace, error) {
	if a.Meta[SnapshotKey] != "" && c.Snapshot != nil {
		return c.Snapshot.Workspace(ctx, a)
	}
	if c.Live != nil {
		return c.Live.Workspace(ctx, a)
	}
	return operate.Workspace{}, fmt.Errorf("operate: no workspace source for asset %s (no snapshot, no live connection)", a.Target)
}
