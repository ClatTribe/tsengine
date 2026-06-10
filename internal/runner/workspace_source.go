package runner

import (
	"context"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// SnapshotKey is the asset Meta key holding the path to a workspace snapshot JSON. The
// MVP WorkspaceSource (below) reads from it; a live IdP/M365 connector replaces this by
// producing the snapshot from the provider API behind the same WorkspaceSource interface.
const SnapshotKey = "snapshot_path"

// SnapshotSource is the MVP WorkspaceSource: it loads the operate.Workspace from the
// JSON file named in the asset's Meta[SnapshotKey]. This lets an operator register a
// workspace asset pointing at an exported snapshot until the live connector lands.
type SnapshotSource struct{}

// Workspace loads the snapshot file referenced by the asset.
func (SnapshotSource) Workspace(_ context.Context, a platform.Asset) (operate.Workspace, error) {
	path := a.Meta[SnapshotKey]
	if path == "" {
		return operate.Workspace{}, fmt.Errorf("operate: workspace asset %s has no %s in Meta", a.Target, SnapshotKey)
	}
	return operate.LoadWorkspace(path)
}
