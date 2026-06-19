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
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
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
	GRC      *grc.GRC         // fold each finding into the compliance system-of-record
	Propose  Proposer         // generate a remediation Action per finding
	Desk     *hitl.Desk       // gate/auto-apply the proposed Action
	Detector *detect.Detector // open/resolve incidents from change between monitoring passes
	// ProposeIncidentResponse is the A-RSP "respond" half: turn a newly-opened incident into
	// a response Action (e.g. a T3 breach-disclosure draft for a critical incident). Wired to
	// remediate.ProposeIncidentResponse by the caller; nil → incidents just open + alert.
	ProposeIncidentResponse func(platform.Incident) (platform.Action, bool)

	// optional webhook auto-registration (event-driven re-scans on connect)
	WebhookSecret string // shared secret stamped on registered hooks (and verified inbound)
	PublicURL     string // platform base URL for the webhook callback
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
	s.registerWebhooks(ctx, conn, c.Kind, tok, assets)
	scanned := 0
	for i := range assets {
		if assets[i].ID == "" {
			assets[i].ID = s.newID("asset")
		}
		if err := s.Store.PutAsset(ctx, assets[i]); err != nil {
			return scanned, err
		}
		if _, _, err := s.scanAsset(ctx, assets[i], platform.TriggerSchedule); err != nil {
			return scanned, err
		}
		scanned++
	}
	return scanned, nil
}

// registerWebhooks installs a push webhook on each discovered repo so future events
// re-scan instantly (event-driven monitoring). Best-effort: only when the connector
// supports it and the platform is configured with a public URL + webhook secret; an
// individual failure is swallowed (the scheduled re-scan still covers the asset).
func (s *Service) registerWebhooks(ctx context.Context, conn connector.Connector, kind, tok string, assets []platform.Asset) {
	reg, ok := conn.(connector.WebhookRegistrar)
	if !ok || s.WebhookSecret == "" || s.PublicURL == "" {
		return
	}
	callback := strings.TrimRight(s.PublicURL, "/") + "/v1/webhooks/" + kind
	for _, a := range assets {
		if full := a.Meta["full_name"]; full != "" {
			_ = reg.RegisterWebhook(ctx, tok, full, callback, s.WebhookSecret)
		}
	}
}

// RescanTenant re-scans every asset a tenant has (the scheduled-monitoring path). It
// runs the full loop per asset and returns how many it scanned; an asset error is
// logged via the returned error but does not stop the rest.
func (s *Service) RescanTenant(ctx context.Context, tenantID string) (int, error) {
	// Kill-switch (agentic-SMB spec OM-3 / TS-5): a halted tenant gets NO new agent
	// activity — scanning is paused along with the write path. The human's already-collected
	// state stays readable; nothing new runs until they disengage.
	if s.halted(ctx, tenantID) {
		return 0, nil
	}
	assets, err := s.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	statuses := s.connStatuses(ctx, tenantID)
	scanned := 0
	var firstErr error
	var current []types.Finding
	for _, a := range assets {
		if connInactive(statuses, a) {
			continue // OM-5 fail-closed: an asset whose connection is unavailable/quarantined is not scanned
		}
		_, fs, err := s.scanAsset(ctx, a, platform.TriggerSchedule)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		current = append(current, fs...)
		scanned++
	}
	// continuous-monitoring: reconcile this pass's findings into incidents (what's NEW,
	// what's RESOLVED since last pass). Runs over the whole tenant — a full pass is the
	// authoritative present state. Only when every asset scanned cleanly, so a partial
	// pass never falsely resolves an incident on an asset that errored.
	if s.Detector != nil && firstErr == nil {
		res, err := s.Detector.Reconcile(ctx, tenantID, current)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		// A-RSP "respond" half: for each NEWLY-OPENED incident, the agent prepares a
		// response. A critical incident yields a T3 breach-disclosure DRAFT that queues for
		// a human signature (it can never auto-apply). Best-effort + optional — omit the
		// proposer and incidents just open + alert as before.
		if s.ProposeIncidentResponse != nil && s.Desk != nil {
			for _, inc := range res.Opened {
				if act, ok := s.ProposeIncidentResponse(inc); ok {
					if _, err := s.Desk.Submit(ctx, act); err != nil && firstErr == nil {
						firstErr = err
					}
				}
			}
		}
	}
	return scanned, firstErr
}

// OnTrigger handles a single provider event (a push) — find the matching asset and
// re-scan it.
func (s *Service) OnTrigger(ctx context.Context, t connector.Trigger) (*platform.Engagement, error) {
	if s.halted(ctx, t.TenantID) { // kill-switch: ignore webhook-driven re-scans while halted
		return nil, nil
	}
	assets, err := s.Store.ListAssets(ctx, t.TenantID)
	if err != nil {
		return nil, err
	}
	statuses := s.connStatuses(ctx, t.TenantID)
	for _, a := range assets {
		if a.Target == t.AssetTarget {
			if connInactive(statuses, a) {
				return nil, nil // OM-5 fail-closed: the matched asset's connection is unavailable/quarantined
			}
			eng, _, err := s.scanAsset(ctx, a, t.Kind)
			return eng, err
		}
	}
	return nil, fmt.Errorf("runner: no asset matches trigger target %q", t.AssetTarget)
}

// connStatuses maps the tenant's connection ids to their status. A nil result (a store
// read error) means "don't know" and is treated as permissive by connInactive — the
// kill-switch (OM-3) is the hard stop; this is the softer per-connection fail-closed.
func (s *Service) connStatuses(ctx context.Context, tenantID string) map[string]string {
	conns, err := s.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, c := range conns {
		m[c.ID] = c.Status
	}
	return m
}

// connInactive reports whether an asset must be skipped because its connection is KNOWN to
// be unavailable (revoked/degraded/quarantined) — the OM-5 / WRD-4 fail-closed check.
// Permissive on missing data: no connection id, an unreadable connection set (nil), or a
// connection the store doesn't know about is NOT blocked (only a deliberate non-active
// status fails closed; an absent record might be a discovery-time race).
func connInactive(statuses map[string]string, a platform.Asset) bool {
	if a.ConnectionID == "" || statuses == nil {
		return false
	}
	st, found := statuses[a.ConnectionID]
	return found && st != platform.ConnActive
}

// halted reports whether the tenant's kill-switch is engaged (Tenant.AgentsHalted). A
// store read error is treated as NOT halted — the switch is opt-in, and a transient error
// must not silently freeze monitoring.
func (s *Service) halted(ctx context.Context, tenantID string) bool {
	t, err := s.Store.GetTenant(ctx, tenantID)
	return err == nil && t.AgentsHalted
}

// scanAsset runs the engine over one asset, persists the findings, and records the
// engagement. Findings carry no tenant field, so isolation rides entirely on the
// store's tenant-scoped PutFinding.
func (s *Service) scanAsset(ctx context.Context, a platform.Asset, trigger string) (*platform.Engagement, []types.Finding, error) {
	eng := platform.Engagement{
		ID: s.newID("eng"), TenantID: a.TenantID, AssetID: a.ID,
		Trigger: trigger, StartedAt: s.now(),
	}
	findings, err := s.Scanner.Scan(ctx, a)
	if err != nil {
		return nil, nil, fmt.Errorf("runner: scan %s: %w", a.Target, err)
	}
	for _, f := range findings {
		if err := s.Store.PutFinding(ctx, a.TenantID, f); err != nil {
			return nil, nil, err
		}
		if err := s.processFinding(ctx, a, f); err != nil {
			return nil, nil, err
		}
	}
	eng.CompletedAt = s.now()
	if err := s.Store.PutEngagement(ctx, eng); err != nil {
		return nil, nil, err
	}
	return &eng, findings, nil
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
