package runner

import (
	"context"
	"fmt"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// proposeKeyDeactivation gives a leaked-AWS-key finding its SECOND action: beside the repository PR
// that scrubs the file, a tier-2 deactivation of the key through the tenant's AWS connection. Two
// actions rather than one because they have different consequences (not merging a PR reverses it;
// a deactivated key stops a workload the moment it is applied) and travel through different
// connections. The desk gates the deactivation; nothing here applies anything.
//
// Grounded (§10): no KeyDeactivate hook, no active AWS connection, or a finding that names no key
// id → no action, never a guess at which key to stop.
func (s *Service) proposeKeyDeactivation(ctx context.Context, a platform.Asset, f types.Finding) error {
	if s.KeyDeactivate == nil || s.Desk == nil || s.Store == nil || a.Type != "repository" {
		return nil
	}
	conns, err := s.Store.ListConnections(ctx, a.TenantID)
	if err != nil {
		return nil // the PR still goes; the deactivation is a second chance, not the only one
	}
	for _, c := range conns {
		if c.Kind != platform.ConnAWS || c.Status != platform.ConnActive {
			continue
		}
		act, ok := s.KeyDeactivate(f, c)
		if !ok {
			return nil
		}
		if _, err := s.Desk.Submit(ctx, stampFindingKeys(act, []types.Finding{f})); err != nil {
			return fmt.Errorf("runner: desk submit (key deactivation): %w", err)
		}
		return nil // one AWS connection is enough; a second would deactivate the same key twice
	}
	return nil
}
