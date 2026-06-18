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
  started_at: string;
  completed_at?: string;
}

export interface ControlState {
  framework: string;
  control_id: string;
  state: string; // met | gap | exception
  evidence_refs?: string[];
}
