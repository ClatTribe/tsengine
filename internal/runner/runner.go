// Package runner is the glue that turns a connected system into continuous, grounded
// scans (docs/autonomous-team.md §3.3). It resolves a Trigger (or a discovery) to the
// tenant's assets, runs the engine over each, persists the findings to the
// system-of-record, and records a signed Engagement.
//
// The engine itself is abstracted behind ScanRunner so the platform glue is testable
// without spinning a sandbox; EngineRunner (engine.go) is the real adapter over
// internal/orchestrator.
package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ScanRunner runs the engine over one asset and returns its grounded findings. The
// real implementation drives internal/orchestrator in a sandbox; tests use a fake.
type ScanRunner interface {
	Scan(ctx context.Context, a platform.Asset) ([]types.Finding, error)
}

// Tokens resolves a connection's vaulted OAuth token (the secret store). Kept as an
// interface so the MVP KMS-envelope impl and a test stub are interchangeable.
type Tokens interface {
	Resolve(ctx context.Context, c platform.Connection) (string, error)
}

// Clock returns the current time (injectable for deterministic tests).
type Clock func() time.Time

// IDGen returns a fresh unique id (injectable for deterministic tests).
type IDGen func() string

// Proposer maps a grounded finding (under its asset) to a remediation Action and
// whether one was produced. Wired to remediate.Propose by the caller — kept as a func
// so runner does not import remediate (which imports runner.Tokens → would cycle).
type Proposer func(types.Finding, platform.Asset) (platform.Action, bool)

// Service ties connectors + the engine + the store together, and (optionally) runs the
// full autonomous loop per finding: GRC control-state update → propose a fix → gate it
// at the HITL desk. The loop collaborators are nil-safe — omit them and Service just
// scans and persists (the Phase-1 behaviour).
type Service struct {
	Store      store.Store
	Connectors *connector.Registry
	Tokens     Tokens
	Scanner    ScanRunner
	Now        Clock
	NewID      IDGen

	// optional autonomous-loop collaborators
	GRC     *grc.GRC   // fold each finding into the compliance system-of-record
	Propose Proposer   // generate a remediation Action per finding
	Desk    *hitl.Desk // gate/auto-apply the proposed Action
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) newID(prefix string) string {
	if s.NewID != nil {
		return prefix + "-" + s.NewID()
	}
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// DiscoverAndScan links a connection's assets into the store and scans each — the
// onboarding path ("connect my GitHub org → see findings").
func (s *Service) DiscoverAndScan(ctx context.Context, c platform.Connection) (int, error) {
	conn, err := s.Connectors.Get(c.Kind)
	if err != nil {
		return 0, err
	}
	tok, err := s.Tokens.Resolve(ctx, c)
	if err != nil {
		return 0, fmt.Errorf("runner: resolve token: %w", err)
	}
	assets, err := conn.Discover(ctx, c, tok)
	if err != nil {
		return 0, fmt.Errorf("runner: discover: %w", err)
	}
	scanned := 0
	for i := range assets {
		if assets[i].ID == "" {
			assets[i].ID = s.newID("asset")
		}
		if err := s.Store.PutAsset(ctx, assets[i]); err != nil {
			return scanned, err
		}
		if _, err := s.scanAsset(ctx, assets[i], platform.TriggerSchedule); err != nil {
			return scanned, err
		}
		scanned++
	}
	return scanned, nil
}

// RescanTenant re-scans every asset a tenant has (the scheduled-monitoring path). It
// runs the full loop per asset and returns how many it scanned; an asset error is
// logged via the returned error but does not stop the rest.
func (s *Service) RescanTenant(ctx context.Context, tenantID string) (int, error) {
	assets, err := s.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	scanned := 0
	var firstErr error
	for _, a := range assets {
		if _, err := s.scanAsset(ctx, a, platform.TriggerSchedule); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		scanned++
	}
	return scanned, firstErr
}

// OnTrigger handles a single provider event (a push) — find the matching asset and
// re-scan it.
func (s *Service) OnTrigger(ctx context.Context, t connector.Trigger) (*platform.Engagement, error) {
	assets, err := s.Store.ListAssets(ctx, t.TenantID)
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		if a.Target == t.AssetTarget {
			return s.scanAsset(ctx, a, t.Kind)
		}
	}
	return nil, fmt.Errorf("runner: no asset matches trigger target %q", t.AssetTarget)
}

// scanAsset runs the engine over one asset, persists the findings, and records the
// engagement. Findings carry no tenant field, so isolation rides entirely on the
// store's tenant-scoped PutFinding.
func (s *Service) scanAsset(ctx context.Context, a platform.Asset, trigger string) (*platform.Engagement, error) {
	eng := platform.Engagement{
		ID: s.newID("eng"), TenantID: a.TenantID, AssetID: a.ID,
		Trigger: trigger, StartedAt: s.now(),
	}
	findings, err := s.Scanner.Scan(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("runner: scan %s: %w", a.Target, err)
	}
	for _, f := range findings {
		if err := s.Store.PutFinding(ctx, a.TenantID, f); err != nil {
			return nil, err
		}
		if err := s.processFinding(ctx, a, f); err != nil {
			return nil, err
		}
	}
	eng.CompletedAt = s.now()
	if err := s.Store.PutEngagement(ctx, eng); err != nil {
		return nil, err
	}
	return &eng, nil
}

// processFinding runs the optional autonomous loop for one finding: update the
// compliance system-of-record, propose a fix, and gate it at the desk. Each step is
// nil-safe; a step error aborts the scan (findings are already persisted).
func (s *Service) processFinding(ctx context.Context, a platform.Asset, f types.Finding) error {
	if s.GRC != nil {
		if err := s.GRC.Apply(ctx, a.TenantID, f); err != nil {
			return fmt.Errorf("runner: grc apply: %w", err)
		}
	}
	if s.Propose != nil && s.Desk != nil {
		act, ok := s.Propose(f, a)
		if ok {
			if _, err := s.Desk.Submit(ctx, act); err != nil {
				return fmt.Errorf("runner: desk submit: %w", err)
			}
		}
	}
	return nil
}
