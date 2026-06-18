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
}

export interface Action {
  id: string;
  tenant_id: string;
  finding_id: string;
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
  answers: QAnswer[];
  yes: number;
  in_progress: number;
}

export interface Asset {
  id: string;
  connection_id: string;
  type: string; // repository | cloud_account | web_application | domain | workspace | ...
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
  Rows: ReportRow[];
  MetCount: number;
  GapCount: number;
  Signer?: string;
  SHA256?: string;
}
