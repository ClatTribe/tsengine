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

import "time"

// Tenant is one customer organization. Every other entity is scoped to a TenantID;
// the store enforces isolation on that key.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Connection kinds — the external systems the platform can link via OAuth.
const (
	ConnGitHub     = "github"
	ConnGitLab     = "gitlab"
	ConnAWS        = "aws"
	ConnGCP        = "gcp"
	ConnGWorkspace = "gworkspace"
	ConnM365       = "m365"
	ConnOkta       = "okta"
	ConnSlack      = "slack"
)

// Connection statuses.
const (
	ConnActive   = "active"
	ConnDegraded = "degraded"
	ConnRevoked  = "revoked"
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
	CreatedAt time.Time `json:"created_at"`
}

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
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id"`
	FindingID    string         `json:"finding_id"`
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

// NeedsApproval reports whether this action must pause for a human (tier-gated).
func (a Action) NeedsApproval() bool { return a.Tier >= GateTier }

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
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Key        string    `json:"key"` // stable identity: "<rule_id>|<endpoint>"
	RuleID     string    `json:"rule_id"`
	Title      string    `json:"title"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`     // IncidentOpen | IncidentResolved
	FindingID  string    `json:"finding_id"` // the finding that opened it
	OpenedAt   time.Time `json:"opened_at"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
	LedgerRef  string    `json:"ledger_ref,omitempty"`
}
