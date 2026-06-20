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
	// AgentsHalted is the global kill-switch (agentic-SMB spec OM-3 / TS-5): when true,
	// the platform performs NO autonomous agent action for this tenant — no new scans and
	// no remediation writes (auto-applied or human-approved alike). It fails closed: a
	// halted tenant's actions queue instead of executing until a human disengages it. The
	// one human "on the loop" can freeze the whole roster instantly.
	AgentsHalted bool `json:"agents_halted,omitempty"`
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
