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
	"log/slog"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/osint"
	"github.com/ClatTribe/tsengine/internal/retest"
	"github.com/ClatTribe/tsengine/internal/sspm"
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

// BatchProposer maps an asset's whole finding set to the MINIMAL set of remediation
// Actions — grouping related alerts into one bulk fix (Aikido "bulk fix" parity).
// Wired to remediate.ProposeBulk by the caller. When set it supersedes the per-finding
// Proposer so the desk receives one action per fix group, not per finding.
type BatchProposer func([]types.Finding, platform.Asset) []platform.Action

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
	// GitHubAPIBase overrides the GitHub REST base for the autonomous SaaS-posture sync
	// (default https://api.github.com). Set only in tests (a fake API server).
	GitHubAPIBase string

	// OSINTFetcher, when set, makes external-exposure OSINT a CONTINUOUSLY-monitored surface:
	// each monitoring pass runs the keyless Certificate-Transparency collector over the tenant's
	// domains (the same crt.sh path as POST /v1/osint/scan), so a newly-exposed host appears as a
	// finding and the Detector opens an incident for it. nil → no continuous OSINT (manual-scan only).
	OSINTFetcher osint.Fetcher

	// optional autonomous-loop collaborators
	GRC          *grc.GRC         // fold each finding into the compliance system-of-record
	Propose      Proposer         // generate a remediation Action per finding
	ProposeBatch BatchProposer    // bulk fix: one Action per fix group (supersedes Propose when set)
	Desk         *hitl.Desk       // gate/auto-apply the proposed Action
	Detector     *detect.Detector // open/resolve incidents from change between monitoring passes
	// ProposeIncidentResponse is the A-RSP "respond" half: turn a newly-opened incident into
	// response Actions (a tier-2 gated containment runbook + a T3 breach-disclosure draft for
	// a critical incident). Wired to remediate.ProposeIncidentResponse by the caller; nil →
	// incidents just open + alert.
	ProposeIncidentResponse func(platform.Incident) ([]platform.Action, bool)

	// AfterScan, when set, auto-invokes the AI Security Engineer (the L2 translate/reasoning pass) so
	// the engineer reviews the estate automatically instead of waiting for a human to click. It fires
	// on any pass with scanned>0; the COST bound + entitlement (AIEnabled) + LLM-availability gates all
	// live INSIDE the injected func (where the store is): it reviews on a NEW incident OR the tenant's
	// FIRST review ever (a newly-connected tenant gets an initial analysis), and SKIPS a static estate
	// re-scanned every pass — so the engine runs continuously without re-spending the LLM idly, and a
	// Free tenant never auto-spends the operator's budget. Best-effort. nil → no auto-review.
	AfterScan func(ctx context.Context, tenantID string, findings []types.Finding, openedIncidents int)

	// AfterPass, when set, fires on EVERY monitoring pass (unconditionally, unlike AfterScan) — the
	// hook for time-driven, change-independent work like running due SCHEDULED pentests. Any gating
	// (is anything due? is the tenant halted?) lives inside the injected func. Best-effort,
	// fire-and-forget. nil → nothing extra runs.
	AfterPass func(ctx context.Context, tenantID string)

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
			// OM-5 fail-closed: an asset whose connection is unavailable/quarantined is not scanned.
			slog.Info("[scan] skipped: connection inactive", "asset", a.ID, "type", a.Type, "target", a.Target)
			continue
		}
		_, fs, err := s.scanAsset(ctx, a, platform.TriggerSchedule)
		if err != nil {
			// Per-asset outcome is logged so a failed/empty scan is VISIBLE — RescanTenant only surfaces the
			// first error to the caller, which used to hide why a given asset produced nothing.
			slog.Warn("[scan] asset errored", "asset", a.ID, "type", a.Type, "target", a.Target, "err", err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		slog.Info("[scan] asset scanned", "asset", a.ID, "type", a.Type, "target", a.Target, "findings", len(fs))
		current = append(current, fs...)
		scanned++
	}
	// Autonomous SaaS-posture: if the tenant has a GitHub connection, run the SSPM checks live
	// via its onboarded token each pass (read-only, grounded — a hardened org adds nothing), so
	// posture findings flow into incidents like any other. Best-effort: a fetch failure (e.g.
	// insufficient scope) is logged + skipped, never failing the pass or falsely resolving.
	current = append(current, s.syncSaaSPosture(ctx, tenantID)...)
	// Autonomous external-exposure (OSINT): each pass, run the keyless Certificate-Transparency
	// collector over the tenant's domains so a newly-exposed host becomes a finding the Detector
	// turns into an incident ("new exposed host → alert" — the EASM continuous-monitoring promise).
	// Best-effort + grounded: nil fetcher / no domains → nil; a clean footprint adds nothing.
	current = append(current, s.syncOSINT(ctx, tenantID)...)
	// continuous-monitoring: reconcile this pass's findings into incidents (what's NEW,
	// what's RESOLVED since last pass). Runs over the whole tenant — a full pass is the
	// authoritative present state. Only when every asset scanned cleanly, so a partial
	// pass never falsely resolves an incident on an asset that errored.
	// Only reconcile (which RESOLVES incidents absent from `current`) when an actual scan established
	// the authoritative present state — i.e. at least one asset was scanned. A pure event-driven tenant
	// (identity / SaaS ingest, no scannable assets) has empty scan output every pass; reconciling it
	// would falsely RESOLVE the incidents the ingest path opened via Detector.OpenFor. Those are
	// event-driven and stay open until a human resolves them. (Mixed scan+ingest tenants still reconcile
	// over scan output — the ingest-incident-survives-a-scan-pass case is a documented follow-on.)
	var openedIncidents int
	if s.Detector != nil && firstErr == nil && scanned > 0 {
		// Runtime-protection escalation (ADR-0007 Phase 0b): a finding whose endpoint is
		// being attacked in production opens an incident regardless of severity floor.
		var attacked map[string]bool
		if evs, err := s.Store.ListRuntimeEvents(ctx, tenantID); err == nil {
			attacked = crossdetect.AttackedKeys(current, evs)
		}
		res, err := s.Detector.Reconcile(ctx, tenantID, current, attacked)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		openedIncidents = len(res.Opened) // the "something changed" signal that triggers the auto-review

		// Fix-verification (KF#4 — "60% don't retest after fixes"): re-test every APPLIED
		// remediation against this pass's authoritative findings. A fix is confirmed "fixed" only
		// when its finding keys are absent (grounded §10); still-present means the fix didn't close
		// it. Best-effort — a store error never aborts the pass; the verdict rides on the action.
		if acts, lerr := s.Store.ListActions(ctx, tenantID); lerr == nil {
			for _, verified := range retest.Verify(acts, current, s.now()) {
				if perr := s.Store.PutAction(ctx, verified); perr != nil && firstErr == nil {
					firstErr = perr
				}
			}
		}
		// A-RSP "respond" half: for each NEWLY-OPENED incident, the agent prepares a
		// response. A critical incident yields a T3 breach-disclosure DRAFT that queues for
		// a human signature (it can never auto-apply). Best-effort + optional — omit the
		// proposer and incidents just open + alert as before.
		if s.ProposeIncidentResponse != nil && s.Desk != nil {
			for _, inc := range res.Opened {
				if acts, ok := s.ProposeIncidentResponse(inc); ok {
					for _, act := range acts {
						if _, err := s.Desk.Submit(ctx, act); err != nil && firstErr == nil {
							firstErr = err
						}
					}
				}
			}
		}
		// Timed auto-escalation (escalation matrix Phase 4): each pass, re-alert OPEN,
		// UNACKNOWLEDGED incidents that have sat past the tenant's ack window — the MDR
		// "page again if no one's on it". No policy / window off → no-op.
		if t, terr := s.Store.GetTenant(ctx, tenantID); terr == nil && t.Escalation != nil && t.Escalation.Enabled && t.Escalation.AckWindowMins > 0 {
			if _, err := s.Detector.EscalateOverdue(ctx, tenantID, t.Escalation.AckWindowMins); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	// Compliance reconciliation: grc.Apply (in processFinding) opens control gaps but never closes
	// one, so a remediated issue's gap would persist forever and the framework would read a stale
	// "non-compliant". Reconcile flips a gap to Met when its driving finding is gone from this pass's
	// `current` (mirrors the incident Detector). Guarded by scanned>0 like the detector — an
	// ingest-only pass must not falsely clear scan-driven gaps.
	if s.GRC != nil && scanned > 0 {
		if _, err := s.GRC.Reconcile(ctx, tenantID, current); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Auto-review: after any pass that scanned assets, give the AI Security Engineer a chance to review
	// the estate automatically. The COST bound (fire only on CHANGE or a tenant's FIRST review, never on
	// idle re-scans of a static estate) + the entitlement/LLM gates all live inside the hook, where the
	// store is available — so a newly-connected tenant gets an initial analysis even without a brand-new
	// incident, while a static estate doesn't re-spend the LLM every monitor pass. Best-effort.
	if s.AfterScan != nil && scanned > 0 {
		s.AfterScan(ctx, tenantID, current, openedIncidents)
	}
	// Time-driven per-pass work (due scheduled pentests) — unconditional; the hook self-gates.
	if s.AfterPass != nil {
		s.AfterPass(ctx, tenantID)
	}
	return scanned, firstErr
}

// syncSaaSPosture runs the live GitHub-org SSPM checks for the tenant each monitoring pass,
// reusing the onboarded GitHub connection's token (no extra credential). Read-only + grounded —
// a hardened org adds nothing. Best-effort: any failure (no GitHub connection, insufficient
// scope, transient API error) yields nil so the pass continues uninterrupted. Findings are both
// persisted (so they appear in Issues like the manual /v1/saas/github_org/sync) and returned so
// the detector reconciles them into incidents this pass.
func (s *Service) syncSaaSPosture(ctx context.Context, tenantID string) []types.Finding {
	if s.Store == nil || s.Tokens == nil || s.NewID == nil {
		return nil
	}
	conns, err := s.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return nil
	}
	var gh *platform.Connection
	for i := range conns {
		if conns[i].Kind == platform.ConnGitHub && conns[i].Status == platform.ConnActive {
			gh = &conns[i]
			break
		}
	}
	if gh == nil {
		return nil
	}
	token, terr := s.Tokens.Resolve(ctx, *gh)
	if terr != nil || token == "" {
		return nil
	}
	snap, ferr := sspm.FetchGitHubOrg(ctx, s.GitHubAPIBase, gh.Account, token, nil)
	if ferr != nil {
		return nil // honestly skipped (logged by the caller's monitoring); never a false finding
	}
	findings := sspm.AssessGitHubOrg(snap, sspm.Options{})
	for i := range findings {
		findings[i].ID = s.NewID()
		_ = s.Store.PutFinding(ctx, tenantID, findings[i])
	}
	return findings
}

// syncOSINT runs the keyless Certificate-Transparency collector (crt.sh) over the tenant's domain
// assets each monitoring pass and assesses the result into grounded external-exposure findings. This
// turns OSINT from a manual-button scan into a continuously-monitored surface: the returned findings
// flow into the Detector, so a host that newly appears in CT (e.g. a forgotten staging subdomain)
// opens an incident — the EASM "new exposure → alert" behaviour, for free, via the existing machinery.
// Best-effort + grounded (§10): no fetcher wired, no domain assets, or a clean footprint → no findings.
func (s *Service) syncOSINT(ctx context.Context, tenantID string) []types.Finding {
	if s.Store == nil || s.NewID == nil || s.OSINTFetcher == nil {
		return nil
	}
	assets, err := s.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return nil
	}
	known := map[string]bool{}
	var domains []string
	for _, a := range assets {
		host := strings.ToLower(strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(a.Target, "https://"), "http://"), "/"))
		if host == "" {
			continue
		}
		known[host] = true
		if a.Type == string(types.AssetDomain) {
			domains = append(domains, host)
		}
	}
	if len(domains) == 0 {
		return nil // nothing to monitor externally (no domain assets) — never a false finding
	}
	snap := osint.CollectCT(ctx, tenantID, domains, known, s.OSINTFetcher)
	findings := osint.Assess(snap, osint.Options{NewID: s.NewID})
	for i := range findings {
		_ = s.Store.PutFinding(ctx, tenantID, findings[i])
	}
	return findings
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
	// Bulk fix: propose the minimal set of remediation Actions for the whole asset
	// (one PR per fix group) instead of one per finding. Supersedes the per-finding
	// Propose (skipped in processFinding when ProposeBatch is set).
	if s.ProposeBatch != nil && s.Desk != nil {
		for _, act := range s.ProposeBatch(findings, a) {
			if _, err := s.Desk.Submit(ctx, stampFindingKeys(act, findings)); err != nil {
				return nil, nil, fmt.Errorf("runner: desk submit (bulk): %w", err)
			}
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
	// Per-finding propose — skipped when a batch (bulk-fix) proposer is set; the asset's
	// findings are then proposed together in scanAsset.
	if s.ProposeBatch == nil && s.Propose != nil && s.Desk != nil {
		act, ok := s.Propose(f, a)
		if ok {
			if _, err := s.Desk.Submit(ctx, stampFindingKeys(act, []types.Finding{f})); err != nil {
				return fmt.Errorf("runner: desk submit: %w", err)
			}
		}
	}
	return nil
}

// stampFindingKeys captures the STABLE finding keys (rule_id|endpoint) of the findings a proposed
// action resolves, so the fix can be re-tested after it's applied (retest.Verify). Single-finding
// actions carry FindingID; bulk actions carry FindingIDs — both are resolved against the findings
// in hand at propose time. A no-op when none resolve (the action stays un-verifiable, never guessed).
func stampFindingKeys(act platform.Action, findings []types.Finding) platform.Action {
	ids := act.FindingIDs
	if len(ids) == 0 && act.FindingID != "" {
		ids = []string{act.FindingID}
	}
	if keys := retest.KeysForIDs(ids, findings); len(keys) > 0 {
		act.FindingKeys = keys
	}
	return act
}
