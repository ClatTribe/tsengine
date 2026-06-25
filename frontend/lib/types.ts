// Mirrors the Go /v1 JSON contracts (pkg/types + pkg/platform). Only the fields the UI uses.

export interface Finding {
  id: string;
  rule_id: string;
  tool: string;
  severity: string;
  title: string;
  description?: string;
  endpoint?: string;
  cwe?: string[];
  mitre_techniques?: string[];
  verification_status?: string;
  confidence?: number;
  threat_intel?: { kev?: unknown; epss?: unknown } | null;
  compliance?: Record<string, string[]> | null;
  // Cloud-to-Code: a runtime cloud finding traced back to the IaC resource +
  // file:line that provisioned it. Present only on cloud findings the
  // correlator confidently linked to source; absent otherwise.
  code_provenance?: CodeProvenance | null;
}

export interface CodeProvenance {
  file: string;
  line: number;
  iac_resource: string;
  matched_on: string;
  match_basis: string;
  confidence: string; // "high" | "medium"
}

// Cross-surface attack path (GET /v1/attack-paths) — a finding on one surface
// that bridges, via a concrete shared identifier, to a crown jewel on another.
export interface AttackStep {
  asset_type: string;
  asset_target: string;
  finding_id: string;
  title: string;
  severity: string;
  verified?: boolean;
  via_entity?: string; // the shared identifier that leads to the NEXT step
  crown_jewel?: boolean;
}

export interface AttackPath {
  severity: string;
  steps: AttackStep[];
}

export interface AttackPaths {
  attack_paths: AttackPath[];
  count: number;
}

// Unified issue (GET /v1/issues) — the same weakness reported by one or more
// scanners across surfaces, collapsed into one row ("one issue, many signals").
export interface Issue {
  key: string;
  title: string;
  severity: string;
  cve?: string;
  endpoint?: string;
  tools: string[];
  count: number;
  confirmed: boolean; // ≥2 independent scanners agree
  finding_ids: string[];
  attacked?: boolean; // endpoint observed under attack in production (runtime signal)
  attack_count?: number;
  // Live-exploitable fusion (the ACSP "active/reachable/exploitable" lens): genuinely live, not
  // just present — under attack, OR internet-exposed on an attack path, OR exposed+serious+corroborated.
  live?: boolean;
  live_reason?: string;
  exposed?: boolean;
  in_attack_path?: boolean;
}

export interface IssuesResponse {
  issues: Issue[];
  count: number;
  raw_findings: number;
  confirmed: number;
  ignored?: number;
  excluded?: number; // findings dropped by custom exclusion rules
  attacked?: number; // issues observed under attack in production
  live?: number; // issues that are genuinely live-exploitable (the ACSP fusion)
}

// A custom noise-filter rule (Aikido "custom rules": exclude paths/packages/conditions).
export interface ExclusionRule {
  id: string;
  tenant_id: string;
  field: string; // rule_id | package | path | cve | any
  pattern: string;
  reason?: string;
  note?: string;
  by?: string;
  at?: string;
}

// Pentest engagement (GET/POST /v1/pentest) — the productized AI-pentest lifecycle.
export interface RulesOfEngagement {
  authorized_targets: string[];
  out_of_scope?: string[];
  max_requests: number;
  rate_per_minute?: number;
  allow_active?: boolean;
  authorized_by?: string;
  consent?: string; // explicit recorded consent statement (required for active mode)
}

export interface PentestEngagement {
  id: string;
  tenant_id: string;
  name: string;
  mode: string; // "passive" | "active"
  status: string; // draft|authorized|running|reporting|complete|retesting|halted
  rules_of_engagement: RulesOfEngagement;
  findings?: Finding[] | null;
  requests_used: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface PentestStats {
  engagements: number;
  active_engagements: number;
  completed_runs: number;
  total_findings: number;
  high_plus: number;
  exploitation_proven: number;
  high_plus_proven: number;
  verified_rate: number; // 0..1
  high_plus_found: boolean;
}

export interface Action {
  id: string;
  tenant_id: string;
  finding_id: string;
  finding_ids?: string[]; // a bulk action resolves >1 finding (one PR, many alerts)
  connection_id?: string;
  kind: string;
  tier: number;
  status: string;
  title?: string;
  payload?: Record<string, unknown>;
  created_at?: string;
}

// Risk register — the vCISO judgment artifact. The engine proposes candidates (Proposed); a named
// human decides treatment (accept/mitigate/transfer/avoid), recorded with owner + rationale + ledger.
export interface Risk {
  id: string;
  tenant_id: string;
  title: string;
  description?: string;
  category?: string;
  likelihood: number; // 1-5
  impact: number; // 1-5
  treatment?: string; // accept | mitigate | transfer | avoid
  status: string; // open | accepted | treating | closed
  owner?: string;
  rationale?: string;
  finding_ids?: string[];
  proposed?: boolean; // agent-seeded candidate, awaiting human triage
  created_at: string;
  decided_at?: string;
  decided_by?: string;
  ledger_ref?: string;
}

export interface RiskSummary {
  total: number;
  open: number;
  accepted: number;
  treating: number;
  closed: number;
  proposed: number;
  by_level: Record<string, number>;
  top_risk_id?: string;
}

export interface RisksResponse {
  risks: Risk[];
  summary: RiskSummary;
}

export interface Incident {
  id: string;
  key: string;
  rule_id: string;
  title: string;
  severity: string;
  status: string; // open | resolved
  finding_id: string;
  attacked?: boolean; // escalated because the issue is under attack in production
  opened_at: string;
  resolved_at?: string;
  acknowledged_at?: string; // a human took ownership → stops timed auto-escalation
  acknowledged_by?: string;
  sla_breach?: SLABreach; // read-time SLA state vs the tenant's policy (absent = not tracked)
}

export interface SLATarget {
  severity: string; // critical | high | medium | low
  ack_hours: number;
  resolve_hours: number;
}
export interface SLAPolicy {
  enabled: boolean;
  targets: SLATarget[];
}
export interface SLABreach {
  severity: string;
  ack_due_at?: string;
  resolve_due_at?: string;
  ack_breached: boolean;
  resolve_breached: boolean;
}

export interface MaintenanceWindow {
  id: string;
  name: string;
  starts_at: string;
  ends_at: string;
  reason?: string;
  created_by?: string;
}

// On-call escalation roster entry (GET /v1/contacts) — who the escalation matrix names.
export interface Contact {
  id: string;
  name: string;
  role?: string;
  email?: string;
  phone?: string;
  order: number;
}

// SOC-performance scorecard (GET /v1/soc-metrics) — grounded in incident timestamps.
export interface SOCMetrics {
  generated_at: string;
  open_incidents: number;
  resolved_incidents: number;
  acknowledged: number;
  unacknowledged: number;
  sla_tracked: number;
  sla_compliant: number;
  sla_breached: number;
  sla_compliance_pct: number;
  mtta_hours: number;
  mttr_hours: number;
  aging_under_1d: number;
  aging_1_7d: number;
  aging_over_7d: number;
}

export interface Connection {
  id: string;
  kind: string;
  status: string;
  account?: string;
  config?: Record<string, string>;
  created_at?: string;
}

export interface EscalationTier {
  min_severity: string; // critical | high | medium | low
  channels: string[]; // slack | pagerduty | teams | discord | webhook
}
export interface EscalationPolicy {
  enabled: boolean;
  ack_window_mins: number;
  tiers: EscalationTier[];
}

export interface Tenant {
  id: string;
  name: string;
  plan?: string;
  created_at?: string;
  agents_halted?: boolean; // global kill-switch: when true, no autonomous agent action runs
}

// AI-BOM (agent capability manifest, WRD-1): what the autonomous agent can touch.
export interface AIBomConnection {
  id: string;
  kind: string;
  account?: string;
  status: string; // "active" | "quarantined" | "degraded" | "revoked"
  scopes?: string[];
  write_scopes?: string[];
  capability: "read-only" | "read-write";
}
export interface AIBom {
  governance: { kill_switch_engaged: boolean; gate_tier: number };
  connections: AIBomConnection[] | null; // Go nil slice → null
  summary: { connections: number; write_capable: number; read_only: number };
}

// A user account within a tenant (password hash never sent by the API).
export interface User {
  id: string;
  tenant_id: string;
  email: string;
  name?: string;
  role: string; // "owner" | "member"
  created_at: string;
  must_change_password?: boolean; // invited member with a temp password; app is gated until they rotate it
}

// Public Trust Center aggregate (safe projection — coverage only, never findings).
export interface TrustView {
  org: string;
  monitored: boolean;
  signed: boolean;
  frameworks: { framework: string; coverage: number; met: number; total: number }[] | null; // Go nil slice → null
  generated_at: string;
}

export interface TrustLink {
  tenant: string;
  token: string;
  path: string;
}

export interface Engagement {
  id: string;
  asset_id: string;
  trigger: string;
  scan_id?: string;
  started_at: string;
  completed_at?: string;
}

// Human-expert review request (platform.ReviewRequest — snake_case json tags).
export interface ReviewRequest {
  id: string;
  subject: string; // "finding" | "action"
  subject_id: string;
  note: string;
  requester?: string;
  status: string; // open | resolved
  resolution?: string;
  reviewer?: string;
  created_at: string;
  resolved_at?: string;
}

// Security questionnaire (grc.Questionnaire — snake_case json tags).
export interface QAnswer {
  id: string;
  domain: string;
  text: string;
  controls?: Record<string, string[]>;
  answer: string; // "Yes" | "In Progress"
  gap_controls?: string[];
  evidence_ids?: string[];
}
export interface Questionnaire {
  tenant_id: string;
  generated_at: string;
  answers: QAnswer[] | null; // Go nil slice → null
  yes: number;
  in_progress: number;
}

export interface Asset {
  id: string;
  connection_id: string;
  type: string; // repository | cloud_account | web_application | api | container_image | ip_address | domain | mobile_application | workspace
  target: string;
  meta?: Record<string, string>;
  discovered_at?: string;
  data_tier?: number; // 1 = customer data, 2 = standard, 3 = low sensitivity
  data_tier_label?: string;
}

export interface ControlState {
  framework: string;
  control_id: string;
  state: string; // met | gap | exception
  evidence_refs?: string[];
}

// One framework's compliance summary (met/gap/total). Returned in a batch by GET /v1/posture so
// the dashboard/compliance/reports pages fetch all frameworks in one call instead of 14.
export interface FrameworkPosture {
  framework: string;
  total: number;
  met: number;
  gap: number;
}
export interface PostureSummary {
  frameworks: FrameworkPosture[];
}

// grc.Report JSON (no json tags on the Go struct → PascalCase keys).
export interface ReportEvidence { FindingID: string; Title: string; Severity: string }
export interface ReportRow { ControlID: string; State: string; Gap: boolean; Evidence?: ReportEvidence[] }
export interface ComplianceReport {
  TenantName: string;
  Title: string;
  Framework: string;
  GeneratedAt: string;
  Rows: ReportRow[] | null; // Go marshals an empty slice as null — callers must guard
  MetCount: number;
  GapCount: number;
  Signer?: string;
  SHA256?: string;
}

export interface SaaSApp {
  name: string;
  count: number;
  scopes: string[];
  admin_consent: boolean;
  verified: boolean;
  sensitive: boolean;
  shadow_it: boolean;
}

// PRBotSettings is the repository PR-review-bot policy. block_severity is the merge-gating floor
// ("off" = comment-only); github_connected reports whether the live post is wired to a GitHub App.
export interface PRBotSettings {
  enabled: boolean;
  block_severity: string;
  github_connected: boolean;
}

// Non-human / AI-agent identity posture (GET /v1/identities) — the ACSP agentic identity lens.
export interface NonHumanIdentity {
  name: string;
  class: string; // ai_agent | automation | integration
  privilege: string; // admin | write | read
  scopes: string[];
  users: number;
  verified: boolean;
  risk: string; // high | medium | low
  risk_reason?: string;
}
export interface IdentitiesResponse {
  identities: NonHumanIdentity[];
  summary: { total: number; ai_agents: number; automations: number; write_or_admin: number; risky: number };
}

export interface SaaSAppsResponse {
  apps: SaaSApp[];
  summary: {
    total_apps: number;
    sensitive_apps: number;
    unverified_apps: number;
    shadow_it_apps: number;
    multi_user_apps: number;
  };
}
