// Package platform holds the multi-tenant domain model for the autonomous security
// team product (docs/autonomous-team.md). These types wrap — never replace — the
// engine's scan/finding contract (pkg/types): the engine finds & proves issues; the
// platform layer owns tenancy, the connected systems it watches, the continuous
// engagements it runs, the remediations it proposes, the human approvals it gates,
// and the GRC control state it maintains.
//
// The package is deliberately dependency-light (stdlib + pkg/types) so the store,
// connector, scheduler, hitl, remediate, and grc packages can all share it without a
// cycle.
package platform

import (
	"strings"
	"time"
)

// Tenant is one customer organization. Every other entity is scoped to a TenantID;
// the store enforces isolation on that key.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// AgentsHalted is the global kill-switch (agentic-SMB spec OM-3 / TS-5): when true,
	// the platform performs NO autonomous agent action for this tenant — no new scans and
	// no remediation writes (auto-applied or human-approved alike). It fails closed: a
	// halted tenant's actions queue instead of executing until a human disengages it. The
	// one human "on the loop" can freeze the whole roster instantly.
	AgentsHalted bool `json:"agents_halted,omitempty"`
	// LLM is the tenant's bring-your-own-LLM config for the agent / autonomous pentest. The
	// API key is sealed (LLMConfig.KeyRef holds only the sealed ref); it is NEVER returned to
	// the client — Redacted() strips it, and every tenant response uses that.
	LLM *LLMConfig `json:"llm,omitempty"`
	// PRBot is the per-tenant policy for the repository PR-review bot (ADR 0010). nil = the
	// default (disabled). The live GitHub post is separately gated on the GitHub App PR scope.
	PRBot *PRBotPolicy `json:"pr_bot,omitempty"`
	// SlackWebhookRef is the secret.Vault-sealed ref for this tenant's OWN Slack Incoming Webhook —
	// where THIS tenant's new-incident heads-ups go (per-tenant routing; the operator-env webhook is
	// the fallback). A webhook URL is a bearer capability, so it is sealed, never plaintext at rest,
	// and never returned to the client — Redacted() strips it; HasSlackWebhook() reports presence.
	SlackWebhookRef string `json:"slack_webhook_ref,omitempty"`
	// Jira is the tenant's OWN Jira instance where file_ticket remediations land (per-tenant; the
	// operator-env Jira is the fallback). BaseURL/Email/Project are plain identifiers; the API token
	// is sealed (TokenRef). Redacted() drops the whole block.
	Jira *JiraConfig `json:"jira,omitempty"`
	// Escalation is the per-tenant incident escalation matrix (the MDR/SOC "who is alerted, how
	// urgently" for a new incident). nil/disabled = today's behaviour (alert every configured
	// channel). No secret material — channel names only.
	Escalation *EscalationPolicy `json:"escalation,omitempty"`
	// SLA is the per-tenant remediation SLA policy (per-severity time-to-acknowledge +
	// time-to-resolve targets). nil/disabled = no SLA tracking. No secret material.
	SLA *SLAPolicy `json:"sla,omitempty"`
	// MaintenanceWindows are planned change-freeze periods. While one is active, the detector
	// opens no new incidents and the escalation matrix pages no one (so a planned deploy doesn't
	// trip the SOC). Resolves still flow. Empty = always-on monitoring.
	MaintenanceWindows []MaintenanceWindow `json:"maintenance_windows,omitempty"`
}

// MaintenanceWindow is a planned period during which alerting is suppressed (a change-freeze /
// deploy window — standard MDR/SOC operations). No secret material.
type MaintenanceWindow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	Reason    string    `json:"reason,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// Active reports whether now falls within the window ([StartsAt, EndsAt)).
func (w MaintenanceWindow) Active(now time.Time) bool {
	return !now.Before(w.StartsAt) && now.Before(w.EndsAt)
}

// InMaintenance reports whether the tenant has any maintenance window active at now (so alerting
// should be suppressed). Returns the first active window for context.
func (t Tenant) InMaintenance(now time.Time) (MaintenanceWindow, bool) {
	for _, w := range t.MaintenanceWindows {
		if w.Active(now) {
			return w, true
		}
	}
	return MaintenanceWindow{}, false
}

// HasSlackWebhook reports whether the tenant has configured its own Slack incident webhook.
func (t Tenant) HasSlackWebhook() bool { return t.SlackWebhookRef != "" }

// EscalationPolicy is the per-tenant incident escalation matrix — the MDR/SOC "who is alerted, and
// how urgently" for a newly-opened incident (PagerDuty/Opsgenie parity + the contractual
// "escalation matrix with contact number"). When Enabled, the incident alerter routes a new
// incident to the channels of the FIRST tier whose MinSeverity the incident meets; if it is not
// acknowledged within AckWindowMins, it escalates to the next tier (timed auto-escalation —
// Phase 2). Disabled/nil = today's behaviour (alert every configured channel on every incident).
type EscalationPolicy struct {
	Enabled       bool             `json:"enabled"`
	AckWindowMins int              `json:"ack_window_mins,omitempty"` // 0 = no timed auto-escalation
	Tiers         []EscalationTier `json:"tiers"`
}

// EscalationTier routes incidents at/above MinSeverity to Channels. Tiers are ordered: tier 0 is
// the first responder; later tiers are escalation targets.
type EscalationTier struct {
	MinSeverity string   `json:"min_severity"` // critical | high | medium | low
	Channels    []string `json:"channels"`     // slack | pagerduty | teams | email | webhook
}

// SLAPolicy is the per-tenant remediation SLA — the time-to-acknowledge + time-to-resolve targets
// a managed-security buyer expects (and the AAI-PO "24x7 SOC" implies: a serious issue must be
// owned and fixed inside a contracted window). Every MDR / vuln-mgmt competitor ships per-severity
// SLAs; this is that, grounded on the incident timestamps (OpenedAt / AcknowledgedAt / ResolvedAt).
type SLAPolicy struct {
	Enabled bool        `json:"enabled"`
	Targets []SLATarget `json:"targets"`
}

// SLATarget is the per-severity window. Hours (not minutes) — SLAs are coarse. 0 = no target for
// that clock (e.g. AckHours 0 → acknowledgement is not SLA-tracked for this severity).
type SLATarget struct {
	Severity     string `json:"severity"`      // critical | high | medium | low
	AckHours     int    `json:"ack_hours"`     // hours from open to acknowledge
	ResolveHours int    `json:"resolve_hours"` // hours from open to resolve
}

// SLABreach is the evaluated SLA state of one incident against the policy.
type SLABreach struct {
	Severity        string    `json:"severity"`
	AckDueAt        time.Time `json:"ack_due_at,omitempty"`
	ResolveDueAt    time.Time `json:"resolve_due_at,omitempty"`
	AckBreached     bool      `json:"ack_breached"`     // not acknowledged in time
	ResolveBreached bool      `json:"resolve_breached"` // not resolved in time
}

// Breached reports whether either clock is breached.
func (b SLABreach) Breached() bool { return b.AckBreached || b.ResolveBreached }

// TargetFor returns the SLA target for a severity (exact match). ok=false when there is no target.
func (p *SLAPolicy) TargetFor(severity string) (SLATarget, bool) {
	if p == nil || !p.Enabled {
		return SLATarget{}, false
	}
	for _, t := range p.Targets {
		if t.Severity == severity {
			return t, true
		}
	}
	return SLATarget{}, false
}

// Evaluate computes the SLA state of an incident against the policy. ok=false when SLA tracking does
// not apply (no policy / disabled / no target for the severity). Grounded on the incident clocks:
//   - ack breach: the incident is not yet acknowledged AND now is past OpenedAt+AckHours;
//   - resolve breach: the incident is not resolved AND now is past OpenedAt+ResolveHours.
//
// A met clock never breaches (an acknowledged incident has no ack breach; a resolved one has no
// resolve breach). A 0-hour target disables that clock. now is injected so it is testable.
func (p *SLAPolicy) Evaluate(inc Incident, now time.Time) (SLABreach, bool) {
	tgt, ok := p.TargetFor(inc.Severity)
	if !ok {
		return SLABreach{}, false
	}
	b := SLABreach{Severity: inc.Severity}
	if tgt.AckHours > 0 {
		b.AckDueAt = inc.OpenedAt.Add(time.Duration(tgt.AckHours) * time.Hour)
		b.AckBreached = !inc.Acknowledged() && now.After(b.AckDueAt)
	}
	if tgt.ResolveHours > 0 {
		b.ResolveDueAt = inc.OpenedAt.Add(time.Duration(tgt.ResolveHours) * time.Hour)
		b.ResolveBreached = inc.Status != IncidentResolved && now.After(b.ResolveDueAt)
	}
	return b, true
}

// severityRank orders severities so a tier's MinSeverity floor can be compared. Higher = worse.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// ChannelsFor returns the channels the FIRST matching tier routes a new incident of the given
// severity to (tiers evaluated in order; a tier matches when the incident severity ≥ its
// MinSeverity). Returns (nil, false) when the policy is nil/disabled/empty or nothing matches —
// the caller then falls back to its default alerting. Pure, so it's unit-tested directly.
func (p *EscalationPolicy) ChannelsFor(severity string) (channels []string, matched bool) {
	if p == nil || !p.Enabled || len(p.Tiers) == 0 {
		return nil, false
	}
	sev := severityRank(severity)
	for _, t := range p.Tiers {
		if sev >= severityRank(t.MinSeverity) && len(t.Channels) > 0 {
			return t.Channels, true
		}
	}
	return nil, false
}

// JiraConfig is a tenant's own Jira ticketing destination. BaseURL/Email/Project are plain;
// TokenRef is the secret.Vault-sealed ref for the API token (never plaintext, never returned).
type JiraConfig struct {
	BaseURL  string `json:"base_url"`
	Email    string `json:"email"`
	Project  string `json:"project"`
	TokenRef string `json:"token_ref,omitempty"`
}

// HasToken reports whether a usable Jira destination is configured (without exposing the token).
func (j *JiraConfig) HasToken() bool {
	return j != nil && j.BaseURL != "" && j.Email != "" && j.Project != "" && j.TokenRef != ""
}

// PRBotPolicy is the per-tenant repository PR-review-bot policy: whether to post inline review
// comments + a merge-gating check-run on a pull request, and the severity at/above which the
// check-run FAILS (blocks merge). No secret material — safe to return to the client.
type PRBotPolicy struct {
	Enabled bool `json:"enabled"`
	// BlockSeverity is the merge-gating floor: a finding at/above it fails the check-run.
	// "" or "off" = comment-only (advisory, never blocks). Else: critical|high|medium|low.
	BlockSeverity string `json:"block_severity"`
}

// LLMConfig is a tenant's configured LLM for engine agent work (the L2 agent, ModeDeep
// pentest, the live bench). Provider/Model are plain; KeyRef is the secret.Vault-sealed ref
// for the API key (never plaintext at rest, never returned to the client — §18.2 inv. 6).
type LLMConfig struct {
	Provider string `json:"provider"` // anthropic | openai | gemini
	Model    string `json:"model"`    // e.g. claude-opus-4-8, gpt-4o, gemini-2.0-flash
	KeyRef   string `json:"key_ref,omitempty"`
}

// HasKey reports whether an API key is configured (without exposing it).
func (c *LLMConfig) HasKey() bool { return c != nil && c.KeyRef != "" }

// Redacted returns a copy of the tenant safe to return to a client: the LLM block (which
// carries the sealed key ref) is dropped. LLM provider/model are served only by the dedicated
// GET /v1/settings/llm endpoint.
func (t Tenant) Redacted() Tenant { t.LLM = nil; t.SlackWebhookRef = ""; t.Jira = nil; return t }

// Connection kinds — the external systems the platform can link via OAuth.
const (
	ConnGitHub      = "github"
	ConnGitLab      = "gitlab"
	ConnBitbucket   = "bitbucket"
	ConnAzureDevOps = "azuredevops"
	ConnAWS         = "aws"
	ConnGCP         = "gcp"
	ConnAzure       = "azure"
	ConnGWorkspace  = "gworkspace"
	ConnM365        = "m365"
	ConnOkta        = "okta"
	ConnSlack       = "slack"
)

// Connection statuses.
const (
	ConnActive   = "active"
	ConnDegraded = "degraded"
	ConnRevoked  = "revoked"
	// ConnQuarantined is a human-set, per-connection kill-switch (agentic-SMB spec WRD-4):
	// the agent takes NO action through this one connection (no scans, no writes) while the
	// rest of the roster keeps running. Like every non-active status it fails the connection
	// closed in the runner + deliverer.
	ConnQuarantined = "quarantined"
)

// Connection is an OAuth-linked external system the agent watches and (for gated
// write actions) acts on. The OAuth token itself is NEVER stored inline — SecretRef
// points at the secret store (KMS-envelope for the MVP).
type Connection struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Kind      string    `json:"kind"`   // ConnGitHub | ConnAWS | ...
	Status    string    `json:"status"` // ConnActive | ConnDegraded | ConnRevoked
	Scopes    []string  `json:"scopes,omitempty"`
	SecretRef string    `json:"secret_ref"` // → secret store, opaque to the platform
	Account   string    `json:"account,omitempty"`
	// Config holds per-connection, NON-secret configuration the customer sets via UX — today the
	// cloud-remediation knobs (remediation_enabled + the customer's own cross-account write role:
	// remediation_role_arn/region for AWS, remediation_impersonate_sa for GCP). These are
	// identifiers, not credentials (like Account), so they live here in the clear; anything
	// actually secret goes through SecretRef/the Vault. Nil for connections that need none.
	Config    map[string]string `json:"config,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// CloudRemediationConfig keys (Connection.Config) — the per-tenant, customer-set cloud write role.
const (
	CfgRemediationEnabled = "remediation_enabled"      // "true" → use the per-tenant write path
	CfgRemediationRole    = "remediation_role_arn"     // AWS: the customer's cross-account write role
	CfgRemediationRegion  = "remediation_region"       // AWS: region for the write call (optional)
	CfgRemediationSA      = "remediation_impersonate_sa" // GCP: the write SA to impersonate
)

// Asset is something discovered under a Connection — a repo, a cloud account, a
// domain. Type uses the engine's asset-type vocabulary (pkg/types.AssetType) so the
// orchestrator can scan it directly.
type Asset struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	ConnectionID string            `json:"connection_id"`
	Type         string            `json:"type"` // repository | cloud_account | web_application | ...
	Target       string            `json:"target"`
	Meta         map[string]string `json:"meta,omitempty"`
	DiscoveredAt time.Time         `json:"discovered_at"`
}

// Engagement trigger kinds.
const (
	TriggerSchedule = "schedule"
	TriggerPush     = "push"
	TriggerDeploy   = "deploy"
	TriggerManual   = "manual"
)

// Engagement is one continuous-monitoring run over an Asset. It wraps an engine scan
// (ScanID → pkg/types.Scan) and points at the signed decision ledger for the run.
type Engagement struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	AssetID     string    `json:"asset_id"`
	Trigger     string    `json:"trigger"`
	ScanID      string    `json:"scan_id,omitempty"`
	LedgerRef   string    `json:"ledger_ref,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// Action kinds — how a remediation is delivered.
const (
	ActOpenPR      = "open_pr"
	ActApplyConfig = "apply_config"
	ActRevokeToken = "revoke_token"
	ActFileTicket  = "file_ticket"
	// ActDraftNotification is the A-RSP incident-response artifact: a DRAFT breach /
	// disclosure communication the agent prepares for a confirmed critical incident. It is
	// always tier-3 (irreversible/legal) — a named human edits and signs it before it is
	// filed or sent; the agent never sends regulatory/customer comms on its own.
	ActDraftNotification = "draft_notification"
)

// Action statuses.
const (
	ActProposed        = "proposed"
	ActPendingApproval = "pending_approval"
	ActApproved        = "approved"
	ActApplied         = "applied"
	ActRejected        = "rejected"
)

// Action is a remediation the agent proposes. Tier is the autonomy tier (§3 of the
// agentic-SMB spec): 0=observe, 1=reversible/low, 2=consequential, 3=irreversible/
// legal. Tier ≥ 2 must be human-gated before it is applied.
type Action struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	FindingID string `json:"finding_id"` // the representative finding (always set — grounding)
	// FindingIDs is the full set a *bulk* action resolves (≥2). Empty for a single-
	// finding action; when set, FindingID is the first/representative of this set. A
	// bulk fix (one PR addressing many related alerts) carries every finding it fixes.
	FindingIDs   []string       `json:"finding_ids,omitempty"`
	ConnectionID string         `json:"connection_id,omitempty"` // the connection that delivers this action
	Kind         string         `json:"kind"`                    // ActOpenPR | ActApplyConfig | ...
	Tier         int            `json:"tier"`                    // 0..3
	Status       string         `json:"status"`                  // ActProposed | ActPendingApproval | ...
	Title        string         `json:"title,omitempty"`
	Payload      map[string]any `json:"payload,omitempty"`
	Approver     string         `json:"approver,omitempty"`
	LedgerRef    string         `json:"ledger_ref,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	DecidedAt    time.Time      `json:"decided_at,omitempty"`
}

// GateTier is the autonomy tier at/above which an Action must be human-approved
// before it is applied. Tier 0/1 auto-apply; 2/3 queue to the HITL desk.
const GateTier = 2

// TierIrreversible (T3) is the autonomy tier for irreversible / legal / business-critical
// actions — regulatory breach notification, customer comms, mass deletion, risk
// acceptance. The agentic-SMB spec (§3, AGT-3, TS-2) is categorical about T3: the agent
// PREPARES, a named human DECIDES and SIGNS — it MUST NOT execute on an auto/"auto"
// approver, and MUST NOT be eligible for any break-glass / pre-authorized auto-apply that
// a lower tier might later get. Enforced in hitl.Desk (a T3 with no named human approver
// is refused, not applied).
const TierIrreversible = 3

// NeedsApproval reports whether this action must pause for a human (tier-gated).
func (a Action) NeedsApproval() bool { return a.Tier >= GateTier }

// NeedsHumanSignature reports whether this action is irreversible (T3) and therefore must
// carry a named human's recorded sign-off — never an automated apply, ever.
func (a Action) NeedsHumanSignature() bool { return a.Tier >= TierIrreversible }

// ControlState statuses.
const (
	ControlMet       = "met"
	ControlGap       = "gap"
	ControlException = "exception"
)

// ControlState is the GRC system-of-record: one control's live status under one
// framework for one tenant, with the evidence that backs it. Continuously updated by
// the grc layer as findings are emitted — the auditable, lock-in artifact.
type ControlState struct {
	TenantID     string    `json:"tenant_id"`
	Framework    string    `json:"framework"`  // soc2 | iso27001 | dpdp | ...
	ControlID    string    `json:"control_id"` // e.g. CC6.1
	State        string    `json:"state"`      // ControlMet | ControlGap | ControlException
	EvidenceRefs []string  `json:"evidence_refs,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ThirdPartyApp is one third-party OAuth integration with access to a tenant's identity
// provider (Google Workspace / M365 / Okta) — the SaaS/app inventory a compliance team
// needs (SOC2 vendor management, shadow-IT review), not just the risky ones we flag as
// findings. Refreshed each operate scan from the live OAuth grants.
type ThirdPartyApp struct {
	TenantID   string   `json:"tenant_id"`
	Provider   string   `json:"provider"` // gworkspace | m365 | okta
	AppID      string   `json:"app_id"`   // the app's display name (or client id)
	Scopes     []string `json:"scopes"`
	Users      int      `json:"users"`       // how many users granted it
	AdminScope bool     `json:"admin_scope"` // holds a directory/admin scope (shadow-admin)
	Verified   bool     `json:"verified"`    // publisher-verified by the provider
}

// Incident statuses.
const (
	IncidentOpen     = "open"
	IncidentResolved = "resolved"
)

// Incident is a durable, deduped security issue tracked across monitoring passes — the
// continuous-monitoring system-of-record that raw findings (overwritten every scan) can't
// provide. The detect layer opens one when a finding at/above the severity threshold
// first appears, and resolves it when that issue stops appearing — so the platform can
// say "this critical issue is NEW since the last pass" and "this one is now fixed",
// timestamped. Key is the stable issue identity (rule + cited entity) so the same issue
// re-detected across scans maps to the same incident.
type Incident struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Key       string `json:"key"` // stable identity: "<rule_id>|<endpoint>"
	RuleID    string `json:"rule_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`     // IncidentOpen | IncidentResolved
	FindingID string `json:"finding_id"` // the finding that opened it
	// Attacked marks an incident opened/escalated because the issue is observed under
	// attack in production (a runtime-protection signal, ADR-0007 Phase 0b) — escalated
	// regardless of the severity floor, since a live exploit attempt is itself urgent.
	Attacked   bool      `json:"attacked,omitempty"`
	OpenedAt   time.Time `json:"opened_at"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
	LedgerRef  string    `json:"ledger_ref,omitempty"`
	// AcknowledgedAt/By record that a human took ownership of the incident (the MDR "I'm on it").
	// An acknowledged incident is never auto-escalated. Zero = unacknowledged.
	AcknowledgedAt time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string    `json:"acknowledged_by,omitempty"`
	// LastEscalatedAt is when the timed auto-escalation last re-alerted this incident, so it
	// re-pings at most once per AckWindowMins instead of every monitoring pass.
	LastEscalatedAt time.Time `json:"last_escalated_at,omitempty"`
	// SLABreach is a TRANSIENT, read-time annotation (the incident's state vs. the tenant's SLA
	// policy) — populated by the API when returning incidents, NEVER persisted. nil = not tracked.
	SLABreach *SLABreach `json:"sla_breach,omitempty"`
}

// Acknowledged reports whether a human has taken ownership of the incident.
func (i Incident) Acknowledged() bool { return !i.AcknowledgedAt.IsZero() }

// Overdue reports whether an OPEN, UNACKNOWLEDGED incident has gone past the ack window and is due
// for a timed auto-escalation re-alert. ackWindowMins ≤ 0 disables timed escalation. It re-pings at
// most once per window (tracked by LastEscalatedAt). now is injected so it's testable.
func (i Incident) Overdue(ackWindowMins int, now time.Time) bool {
	if ackWindowMins <= 0 || i.Status != IncidentOpen || i.Acknowledged() {
		return false
	}
	window := time.Duration(ackWindowMins) * time.Minute
	if now.Sub(i.OpenedAt) < window {
		return false // still within the first response window
	}
	// re-ping only if we haven't escalated yet, or the last escalation is itself a window old
	return i.LastEscalatedAt.IsZero() || now.Sub(i.LastEscalatedAt) >= window
}

// ReviewRequest statuses.
const (
	ReviewOpen     = "open"
	ReviewResolved = "resolved"
)

// ReviewRequest is a human-expert review the tenant asks for on a finding or a
// IgnoreRule suppresses a unified issue from the active list — the issue-lifecycle
// "ignore / accept-risk / false-positive" control. Keyed by the issue's dedup key
// (so it survives re-scans). Carries who suppressed it, when, and why, so the
// suppression is itself auditable (and reversible via un-ignore).
type IgnoreRule struct {
	TenantID string    `json:"tenant_id"`
	IssueKey string    `json:"issue_key"`
	Reason   string    `json:"reason"`         // "false_positive" | "accepted_risk" | free text
	Note     string    `json:"note,omitempty"` // optional human explanation
	By       string    `json:"by,omitempty"`   // who suppressed it
	At       time.Time `json:"at"`
}

// ExclusionRule is a PATTERN-based noise filter (Aikido "custom rules": exclude
// specific paths, packages, conditions). Unlike IgnoreRule (which suppresses one
// exact issue by its dedup key), an ExclusionRule drops every finding whose chosen
// attribute matches a glob — applied before findings are unified, so excluded noise
// disappears from the issue list entirely. Carries who/why/when, so it's auditable
// and reversible like a suppression.
type ExclusionRule struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenant_id"`
	Field    string    `json:"field"`   // rule_id | package | path | cve | any
	Pattern  string    `json:"pattern"` // glob with '*' wildcards (case-insensitive), e.g. "trivy::CVE-2021-*", "lodash", "*/test/*"
	Reason   string    `json:"reason,omitempty"`
	Note     string    `json:"note,omitempty"`
	By       string    `json:"by,omitempty"`
	At       time.Time `json:"at"`
}

// Exclusion field constants (the attribute an ExclusionRule.Pattern matches against).
const (
	ExclByRule    = "rule_id"
	ExclByPackage = "package"
	ExclByPath    = "path"
	ExclByCVE     = "cve"
	ExclByAny     = "any"
)

// RuntimeEvent is a single attack observation from an in-app firewall / RASP sensor
// (Runtime Protection, ADR-0007 Phase 0 — e.g. the OSS "Zen" firewall running in the
// customer's app). tsengine consumes it as a signal; it does NOT block — the sensor
// does. The platform's value is correlating these with scan-time findings: a finding
// on an endpoint that is ALSO being attacked in production is observed-in-the-wild,
// the strongest exploitability signal there is.
type RuntimeEvent struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	App        string    `json:"app,omitempty"`         // the app/service that reported it
	AttackKind string    `json:"attack_kind,omitempty"` // sql_injection | ssrf | path_traversal | xss | ...
	Endpoint   string    `json:"endpoint,omitempty"`    // the route the attack hit
	Sink       string    `json:"sink,omitempty"`        // the dangerous sink reached, if known
	SourceIP   string    `json:"source_ip,omitempty"`   // the attacker IP (informational)
	Blocked    bool      `json:"blocked"`               // did the sensor block it (vs monitor-only)
	Source     string    `json:"source,omitempty"`      // sensor name (e.g. "zen")
	OccurredAt time.Time `json:"occurred_at"`
}

// proposed action — the "AI + a human" trust model SMB security buyers expect
// (a managed-SOC / vCISO escalation). It is request-and-resolve, tenant-scoped,
// and signed into the ledger like every other decision (§18.2 inv. 4). The agent
// keeps working; this is the deliberate human-in-the-loop escape hatch.
type ReviewRequest struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Subject    string    `json:"subject"`    // "finding" | "action"
	SubjectID  string    `json:"subject_id"` // the finding/action id under review
	Note       string    `json:"note"`       // why the tenant wants an expert to look
	Requester  string    `json:"requester,omitempty"`
	Status     string    `json:"status"` // ReviewOpen | ReviewResolved
	Resolution string    `json:"resolution,omitempty"`
	Reviewer   string    `json:"reviewer,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
}
