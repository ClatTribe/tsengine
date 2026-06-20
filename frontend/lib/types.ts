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
}

export interface IssuesResponse {
  issues: Issue[];
  count: number;
  raw_findings: number;
  confirmed: number;
  ignored?: number;
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

export interface Incident {
  id: string;
  key: string;
  rule_id: string;
  title: string;
  severity: string;
  status: string; // open | resolved
  finding_id: string;
  opened_at: string;
  resolved_at?: string;
}

export interface Connection {
  id: string;
  kind: string;
  status: string;
  account?: string;
  created_at?: string;
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
}

export interface ControlState {
  framework: string;
  control_id: string;
  state: string; // met | gap | exception
  evidence_refs?: string[];
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
