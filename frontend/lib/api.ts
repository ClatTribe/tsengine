import "server-only";
import { getSession, apiBase, type Session } from "./auth";
import type { AIBom, Action, Asset, AttackPaths, ComplianceProfile, ComplianceReadiness, ComplianceReport, ComplianceScope, CustomControl, CustomFramework, CustomFrameworkPosture, Connection, Contact, ControlState, Engagement, EscalationPolicy, ExclusionRule, Finding, Incident, IssuesResponse, PentestEngagement, PentestStats, PostureSummary, PRBotSettings, Questionnaire, ReviewRequest, MaintenanceWindow, IdentitiesResponse, Risk, RisksResponse, AuditEngagement, AuditsResponse, Policy, ProgramResponse, Practitioner, PractitionersResponse, SaaSAppsResponse, SLAPolicy, SOCMetrics, Tenant, TrustLink, User } from "./types";

// Server-side client for the Go /v1 API. Every call carries the session's bearer token +
// X-Tenant-ID; the browser is never involved (no CORS, no token exposure). Reads are
// cacheless (always fresh — this is live security state). call() throws on any failure;
// auth (no session) is handled by the (app) layout's getSession redirect, so callers here
// can assume a session exists.

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit, session?: Session): Promise<T> {
  const s = session ?? (await getSession());
  if (!s) throw new ApiError(401, "no session");
  const res = await fetch(apiBase() + path, {
    ...init,
    headers: {
      Authorization: `Bearer ${s.token}`,
      "X-Tenant-ID": s.tenant,
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });
  if (!res.ok) throw new ApiError(res.status, `${path}: HTTP ${res.status}`);
  const ct = res.headers.get("content-type") ?? "";
  return (ct.includes("application/json") ? await res.json() : await res.text()) as T;
}

/** Like call() but never throws — returns a fallback. For non-critical dashboard widgets.
 * Also coerces a null/undefined body to the fallback: the Go API serializes an empty slice
 * (no findings, no pending approvals — a normal "all clear" state) as JSON `null`, and a
 * null reaching `.length`/`.map` in a Server Component would 500 the page. */
async function safe<T>(path: string, fallback: T): Promise<T> {
  try {
    const r = await call<T>(path);
    return r ?? fallback;
  } catch {
    return fallback;
  }
}

/** Like call() but returns null on a GENUINE 404 (the entity truly doesn't exist) and RE-THROWS
 * any other failure (transient / 5xx / API unreachable). A detail page can then notFound() on
 * null but let a transient error hit the recoverable error boundary — so an API hiccup never
 * masquerades as "this page doesn't exist" (the bug class behind the compliance 404). */
async function getOr404<T>(path: string): Promise<T | null> {
  try {
    return await call<T>(path);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

export const api = {
  findings: () => safe<Finding[]>("/v1/findings", []),
  // Uses call() (not safe()) so a transient list-fetch failure THROWS → the recoverable error
  // boundary, rather than silently yielding [] → "finding not found" → a wrong 404. A successful
  // fetch with the id genuinely absent still returns null → the page's notFound().
  finding: async (id: string) => (await call<Finding[]>("/v1/findings")).find((f) => f.id === id) ?? null,
  incidents: (status?: "all") => safe<Incident[]>(`/v1/incidents${status ? "?status=all" : ""}`, []),
  // Take ownership of an open incident → stops the timed auto-escalation (the MDR "I'm on it").
  ackIncident: (id: string, by?: string) =>
    call<Incident>(`/v1/incidents/${id}/ack`, { method: "POST", body: JSON.stringify({ by: by ?? "" }) }),
  attackPaths: () => safe<AttackPaths>("/v1/attack-paths", { attack_paths: [], count: 0 }),

  // Risk register (vCISO artifact) — list + board summary; seed candidates from findings (grounded);
  // and the HITL treatment decision (a named human accepts/treats → signed ledger).
  risks: () =>
    safe<RisksResponse>("/v1/risks", {
      risks: [],
      summary: { total: 0, open: 0, accepted: 0, treating: 0, closed: 0, proposed: 0, by_level: {} },
    }),
  seedRisks: () => call<{ seeded: Risk[]; count: number }>("/v1/risks/seed", { method: "POST" }),
  decideRisk: (id: string, body: { treatment: string; owner: string; rationale?: string }) =>
    call<Risk>(`/v1/risks/${id}/decision`, { method: "POST", body: JSON.stringify(body) }),

  // Audit engagements — "audit-ready, not the audit". The external auditor's per-control attestation
  // is the HITL; the product seeds the controls to attest from posture.
  audits: () => safe<AuditsResponse>("/v1/audits", { audits: [] }),
  createAudit: (body: { framework: string; audit_type: string; auditor_name: string; auditor_firm?: string; auditor_email?: string }) =>
    call<AuditEngagement>("/v1/audits", { method: "POST", body: JSON.stringify(body) }),
  attestControl: (id: string, body: { control_id: string; verdict: string; note?: string; attested_by: string }) =>
    call<AuditEngagement>(`/v1/audits/${id}/attest`, { method: "POST", body: JSON.stringify(body) }),
  issueAudit: (id: string) => call<AuditEngagement>(`/v1/audits/${id}/issue`, { method: "POST" }),

  // Security program (vCISO) — policy register; a named owner publishes (HITL), members acknowledge.
  program: () =>
    safe<ProgramResponse>("/v1/program", {
      policies: [],
      summary: { total: 0, published: 0, draft: 0, team_size: 0, fully_acked: 0, ack_coverage_pct: 0 },
    }),
  seedProgram: () => call<{ seeded: Policy[]; count: number }>("/v1/program/seed", { method: "POST" }),

  // Practitioner layer — who provides the human-in-the-loop (service model + named experts of record).
  practitioners: () => safe<PractitionersResponse>("/v1/practitioners", { service_model: "self_serve", practitioners: [] }),
  setServiceModel: (model: string) => call("/v1/settings/service-model", { method: "PUT", body: JSON.stringify({ service_model: model }) }),
  addPractitioner: (body: { name: string; firm?: string; credential?: string; capacity: string; email?: string; scope?: string[] }) =>
    call<Practitioner>("/v1/practitioners", { method: "POST", body: JSON.stringify(body) }),
  deletePractitioner: (id: string) => call(`/v1/practitioners/${id}`, { method: "DELETE" }),
  publishPolicy: (id: string, owner: string) =>
    call<Policy>(`/v1/program/${id}/publish`, { method: "POST", body: JSON.stringify({ owner }) }),
  ackPolicy: (id: string, user: string) =>
    call<Policy>(`/v1/program/${id}/ack`, { method: "POST", body: JSON.stringify({ user }) }),

  // Add a standalone scan target (web app / API / domain / IP / container image) — the input the
  // connectors don't cover. The caller must attest authorization; the server SSRF-screens the target.
  addAsset: (type: string, target: string, authorized: boolean) =>
    call<Asset>("/v1/assets", { method: "POST", body: JSON.stringify({ type, target, authorized }) }),

  // OSINT external-exposure view — the attacker's-eye footprint (breaches, leaks, exposed hosts,
  // typosquats, public exposure, advisories), folded into the same finding graph.
  osint: () =>
    safe<{ total: number; summary: { label: string; count: number }[]; findings: Finding[] }>(
      "/v1/osint",
      { total: 0, summary: [], findings: [] },
    ),

  // Run a LIVE keyless OSINT scan (Certificate Transparency / crt.sh) over the tenant's domains.
  osintScan: () =>
    call<{ source: string; domains_scanned: number; hosts_discovered: number; findings_detected: number; assets_pivoted: number }>(
      "/v1/osint/scan",
      { method: "POST", body: "{}" },
    ),

  // AI autofix — an LLM-generated code patch for one finding (competitor parity: Snyk/Aikido/Copilot).
  autofix: (id: string) =>
    call<{ finding_id: string; title: string; rule_id: string; fix: string }>(
      `/v1/findings/${id}/autofix`,
      { method: "POST", body: "{}" },
    ),

  // vCISO remediation guidance — concrete, grounded fix steps for a framework's control gaps.
  complianceRemediation: (framework: string) =>
    call<{ framework: string; title: string; gap_count: number; plan: string }>(
      `/v1/compliance/${framework}/remediation`,
      { method: "POST", body: "{}" },
    ),

  // L2 translator — run the Lead over the tenant's findings → the plain-English consultant brief.
  l2Translate: () =>
    call<{
      summary: { executive_summary?: string; methodology?: string; recommendations?: string } | null;
      reports: Finding[];
      iterations: number;
      stop_reason: string;
      cost_usd: number;
      model: string;
    }>("/v1/l2/translate", { method: "POST", body: "{}" }),

  // AI Cloud Engineer — the cloud-agent's proven attack paths (read-only view) + whether a run is possible.
  cloudInvestigation: () =>
    safe<{ total: number; enabled: boolean; paths: Finding[] }>("/v1/cloud/investigate", { total: 0, enabled: false, paths: [] }),

  // SaaS-app discovery view (SSPM) — inventory + portfolio summary over the connected IdPs' grants.
  saasApps: () =>
    safe<SaaSAppsResponse>("/v1/saas-apps", {
      apps: [],
      summary: { total_apps: 0, sensitive_apps: 0, unverified_apps: 0, shadow_it_apps: 0, multi_user_apps: 0 },
    }),
  // Non-human / AI-agent identity posture (the ACSP agentic identity lens) over the OAuth grants.
  identities: () =>
    safe<IdentitiesResponse>("/v1/identities", {
      identities: [],
      summary: { total: 0, ai_agents: 0, automations: 0, write_or_admin: 0, risky: 0 },
    }),
  issues: (showIgnored?: boolean) =>
    safe<IssuesResponse>(`/v1/issues${showIgnored ? "?show=ignored" : ""}`, { issues: [], count: 0, raw_findings: 0, confirmed: 0, ignored: 0 }),
  pentests: () => safe<PentestEngagement[]>("/v1/pentest", []),
  // getOr404 → null only when the engagement genuinely doesn't exist (page notFound()); a
  // transient/5xx error throws to the recoverable error boundary instead of a false 404.
  pentest: (id: string) => getOr404<PentestEngagement>(`/v1/pentest/${id}`),
  pentestStats: () =>
    safe<PentestStats>("/v1/pentest/stats", {
      engagements: 0, active_engagements: 0, completed_runs: 0, total_findings: 0,
      high_plus: 0, exploitation_proven: 0, high_plus_proven: 0, verified_rate: 0, high_plus_found: false,
    }),
  approvals: () => safe<Action[]>("/v1/approvals", []),
  connections: () => safe<Connection[]>("/v1/connections", []),
  tenant: () => safe<Tenant | null>("/v1/tenant", null),
  aiBom: () => safe<AIBom | null>("/v1/ai-bom", null), // agent capability manifest (what the automation can touch)
  trustLink: () => safe<TrustLink | null>("/v1/trust-link", null),
  assets: () => safe<Asset[]>("/v1/assets", []),
  engagements: () => safe<Engagement[]>("/v1/engagements", []),
  posture: (framework: string) => safe<ControlState[]>(`/v1/posture/${framework}`, []),
  // All-framework posture summary in ONE call (replaces fanning out 14 per-framework posture
  // requests on the dashboard/compliance/reports pages).
  postureSummary: () => safe<PostureSummary>("/v1/posture", { frameworks: [] }),
  // Compliance scope (before-analysis): the customer's target frameworks + applicability profile.
  complianceScope: () =>
    safe<ComplianceScope>("/v1/settings/compliance-scope", {
      target_frameworks: [],
      compliance_profile: { handles_phi: false, processes_cards: false, sells_to_gov: false, eu_data_subjects: false, india_data_subject: false, public_company: false },
      suggested: [],
    }),
  setComplianceScope: (body: { target_frameworks: string[]; compliance_profile: ComplianceProfile }) =>
    call<ComplianceScope>("/v1/settings/compliance-scope", { method: "PUT", body: JSON.stringify(body) }),

  // Bring-your-own-framework — define a custom framework; its posture derives from live findings.
  customFrameworks: () =>
    safe<{ custom_frameworks: CustomFramework[] }>("/v1/custom-frameworks", { custom_frameworks: [] }),
  addCustomFramework: (body: { name: string; description?: string; controls: CustomControl[] }) =>
    call<CustomFramework>("/v1/custom-frameworks", { method: "POST", body: JSON.stringify(body) }),
  deleteCustomFramework: (id: string) => call(`/v1/custom-frameworks/${id}`, { method: "DELETE" }),
  customFrameworkPosture: (id: string) =>
    safe<CustomFrameworkPosture | null>(`/v1/custom-frameworks/${id}/posture`, null),

  // Compliance scoping (before-analysis): the connect-this-first readiness checklist for the target
  // frameworks — what to wire up so we can actually assess, reinforcing no-false-compliant.
  complianceReadiness: () =>
    safe<ComplianceReadiness>("/v1/compliance/readiness", { target_frameworks: [], integrations: [], manual_areas: [], connected: 0, recommended: 0, note: "" }),
  report: (framework: string) => safe<ComplianceReport | null>(`/v1/compliance/${framework}/report?format=json`, null),
  questionnaire: () => safe<Questionnaire | null>("/v1/questionnaire", null),
  reviews: () => safe<ReviewRequest[]>("/v1/reviews", []),
  me: () => safe<User | null>("/v1/auth/me", null),
  team: () => safe<User[]>("/v1/auth/team", []),

  // writes (Server Actions call these)
  decide: (id: string, approve: boolean, approver: string) =>
    call<Action>(`/v1/approvals/${id}`, {
      method: "POST",
      body: JSON.stringify({ approver, approve }),
    }),
  // 202 + a job (async, the platform default) or { assets_scanned } (synchronous fallback).
  rescan: () => call<{ assets_scanned?: number; id?: string; status?: string; kind?: string }>("/v1/rescan", { method: "POST" }),

  // Change the signed-in user's password (also clears the forced-rotation flag for an
  // invited member). The session stays valid afterward.
  changePassword: (current: string, next: string) =>
    call<{ ok: boolean }>("/v1/auth/password", {
      method: "POST",
      body: JSON.stringify({ current_password: current, new_password: next }),
    }),

  // Engage/disengage the global kill-switch — halts (or resumes) ALL autonomous agent
  // action for the tenant. Returns the updated tenant.
  killSwitch: (halted: boolean) =>
    call<Tenant>("/v1/killswitch", { method: "POST", body: JSON.stringify({ halted }) }),

  // Quarantine (or restore) ONE connection — the per-agent kill-switch (WRD-4). A
  // quarantined connection is skipped for scans and refused for writes.
  quarantineConnection: (id: string, quarantined: boolean) =>
    call<Connection>(`/v1/connections/${id}/quarantine`, { method: "POST", body: JSON.stringify({ quarantined }) }),

  // Set this cloud connection's per-tenant remediation write role (Bucket B — the customer's
  // OWN cross-account role/SA, used at HITL-approved remediation time). AWS needs role_arn;
  // GCP needs impersonate_sa; Azure just the enable flag (subscription = the connection's account).
  setCloudRemediation: (
    id: string,
    cfg: { enabled: boolean; role_arn?: string; region?: string; impersonate_sa?: string },
  ) => call<Connection>(`/v1/connections/${id}/cloud-remediation`, { method: "POST", body: JSON.stringify(cfg) }),

  // Tier an asset by customer-data exposure (1 = customer data, 2 = standard, 3 = low). The
  // tier raises/lowers the risk-adjusted ranking of that asset's findings.
  setAssetDataTier: (id: string, tier: number) =>
    call<Asset>(`/v1/assets/${id}/data-tier`, { method: "POST", body: JSON.stringify({ tier }) }),

  // Configure authenticated scanning for a web asset — a login flow the scanner replays +
  // validates each scan (credentials are sealed server-side; never returned).
  setLoginFlow: (id: string, flow: unknown) =>
    call<{ asset_id: string; auth_type: string; configured: boolean }>(`/v1/assets/${id}/login-flow`, {
      method: "POST",
      body: JSON.stringify(flow),
    }),

  // Configure the BOLA/BFLA authorization test for an api asset — two identities + the
  // object-bearing operations to test (auth headers are sealed server-side; never returned).
  setAuthzTest: (id: string, cfg: unknown) =>
    call<{ asset_id: string; operations: number; configured: boolean }>(`/v1/assets/${id}/authz-test`, {
      method: "POST",
      body: JSON.stringify(cfg),
    }),

  // Per-tenant LLM config for the engine agent / autonomous pentest. GET reports provider +
  // model + whether a key is set (never the key). PUT sets provider/model and seals the key
  // server-side (an empty api_key keeps the existing key).
  // Auto-triage funnel: of all raw findings, how many the engine handled automatically
  // (excluded / deduped / suppressed) before a human had to look — the "% auto-triaged" metric.
  triageFunnel: () =>
    safe<{ raw_findings: number; excluded: number; deduped: number; suppressed: number; actionable_issues: number; confirmed_issues: number; auto_triaged: number; auto_triage_rate: number }>(
      "/v1/triage-funnel",
      { raw_findings: 0, excluded: 0, deduped: 0, suppressed: 0, actionable_issues: 0, confirmed_issues: 0, auto_triaged: 0, auto_triage_rate: 0 },
    ),

  llmSettings: () =>
    safe<{ provider: string; model: string; has_key: boolean }>("/v1/settings/llm", { provider: "", model: "", has_key: false }),
  setLLMConfig: (provider: string, model: string, apiKey: string) =>
    call<{ provider: string; model: string; has_key: boolean }>("/v1/settings/llm", {
      method: "PUT",
      body: JSON.stringify({ provider, model, api_key: apiKey }),
    }),

  // Repository PR-review-bot policy: enable inline review + a merge-gating check-run, and the
  // severity floor that fails the check. github_connected reports whether the live post is wired.
  prBotSettings: () =>
    safe<PRBotSettings>("/v1/settings/pr-bot", { enabled: false, block_severity: "off", github_connected: false }),
  setPRBotSettings: (enabled: boolean, blockSeverity: string) =>
    call<{ enabled: boolean; block_severity: string; saved: boolean }>("/v1/settings/pr-bot", {
      method: "PUT",
      body: JSON.stringify({ enabled, block_severity: blockSeverity }),
    }),

  // Live GitHub-org SaaS-posture sync — runs the SSPM checks via the onboarded GitHub token (no
  // posted snapshot). Returns how many posture findings were stored (they flow into issues/incidents).
  syncGitHubPosture: () =>
    call<{ provider: string; source: string; org: string; findings_detected: number }>(
      "/v1/saas/github_org/sync", { method: "POST" },
    ),

  // Per-tenant Jira ticketing destination (Bucket B). GET reports base/email/project + has_token
  // (never the token); PUT seals the token server-side. An empty base_url clears it.
  jiraSettings: () =>
    safe<{ base_url: string; email: string; project: string; has_token: boolean }>(
      "/v1/settings/jira", { base_url: "", email: "", project: "", has_token: false },
    ),
  setJiraSettings: (cfg: { base_url: string; email: string; project: string; api_token: string }) =>
    call<{ base_url: string; email: string; project: string; has_token: boolean }>("/v1/settings/jira", {
      method: "PUT",
      body: JSON.stringify(cfg),
    }),

  // Per-tenant incident escalation matrix (MDR/SOC): severity-tiered routing to alert channels.
  escalationSettings: () =>
    safe<EscalationPolicy>("/v1/settings/escalation", { enabled: false, ack_window_mins: 0, tiers: [] }),
  setEscalationSettings: (pol: EscalationPolicy) =>
    call<EscalationPolicy>("/v1/settings/escalation", { method: "PUT", body: JSON.stringify(pol) }),

  // Per-tenant remediation SLA policy: per-severity time-to-acknowledge + time-to-resolve targets.
  slaSettings: () => safe<SLAPolicy>("/v1/settings/sla", { enabled: false, targets: [] }),
  setSLASettings: (pol: SLAPolicy) =>
    call<SLAPolicy>("/v1/settings/sla", { method: "PUT", body: JSON.stringify(pol) }),

  // SOC-performance scorecard (SLA compliance %, MTTA/MTTR, aging) over the tenant's incidents.
  socMetrics: () =>
    safe<SOCMetrics>("/v1/soc-metrics", {
      generated_at: "", open_incidents: 0, resolved_incidents: 0, acknowledged: 0, unacknowledged: 0,
      sla_tracked: 0, sla_compliant: 0, sla_breached: 0, sla_compliance_pct: 0, mtta_hours: 0, mttr_hours: 0,
      aging_under_1d: 0, aging_1_7d: 0, aging_over_7d: 0,
    }),

  // On-call escalation roster (names + numbers the escalation matrix references).
  contacts: () => safe<Contact[]>("/v1/contacts", []),
  addContact: (c: { name: string; role?: string; email?: string; phone?: string; order: number }) =>
    call<Contact>("/v1/contacts", { method: "POST", body: JSON.stringify(c) }),
  deleteContact: (id: string) => call<{ deleted: string }>(`/v1/contacts/${id}`, { method: "DELETE" }),

  // Planned change-freeze windows (suppress alerting while active).
  maintenanceWindows: () => safe<MaintenanceWindow[]>("/v1/maintenance-windows", []),
  addMaintenanceWindow: (w: { name: string; starts_at: string; ends_at: string; reason?: string }) =>
    call<MaintenanceWindow>("/v1/maintenance-windows", { method: "POST", body: JSON.stringify(w) }),
  deleteMaintenanceWindow: (id: string) =>
    call<{ deleted: string }>(`/v1/maintenance-windows/${id}`, { method: "DELETE" }),

  // Per-tenant Slack incident webhook (Bucket B). GET reports only presence; PUT seals the URL
  // server-side and never returns it. An empty string clears it (revert to the operator fallback).
  notifySettings: () => safe<{ has_slack_webhook: boolean }>("/v1/settings/notifications", { has_slack_webhook: false }),
  setNotifySettings: (slackWebhook: string) =>
    call<{ has_slack_webhook: boolean }>("/v1/settings/notifications", {
      method: "PUT",
      body: JSON.stringify({ slack_webhook: slackWebhook }),
    }),

  // Create + authorize a pentest engagement (the API enforces the active-mode
  // authorization gate; an unauthorized active engagement / empty scope → 400).
  createPentest: (body: {
    name: string;
    mode: string;
    rules_of_engagement: { authorized_targets: string[]; max_requests: number; allow_active?: boolean; authorized_by?: string; consent?: string };
  }) => call<PentestEngagement>("/v1/pentest", { method: "POST", body: JSON.stringify(body) }),
  runPentest: (id: string) => call<PentestEngagement>(`/v1/pentest/${id}/run`, { method: "POST" }),
  // Named human sign-off on the VAPT report (the HITL accountability layer).
  signoffPentest: (id: string, body: { signer: string; role?: string; statement?: string }) =>
    call<PentestEngagement>(`/v1/pentest/${id}/signoff`, { method: "POST", body: JSON.stringify(body) }),

  // Suppress (ignore / accept-risk) a unified issue, or restore a suppressed one.
  ignoreIssue: (key: string, reason: string, note?: string) =>
    call<unknown>("/v1/issues/ignore", { method: "POST", body: JSON.stringify({ key, reason, note: note ?? "" }) }),
  unignoreIssue: (key: string) =>
    call<unknown>("/v1/issues/unignore", { method: "POST", body: JSON.stringify({ key }) }),

  // Custom exclusion rules (path/package/rule-id/cve glob noise filters).
  exclusions: () => safe<{ exclusions: ExclusionRule[]; count: number }>("/v1/exclusions", { exclusions: [], count: 0 }),
  addExclusion: (field: string, pattern: string, reason?: string) =>
    call<ExclusionRule>("/v1/exclusions", { method: "POST", body: JSON.stringify({ field, pattern, reason: reason ?? "" }) }),
  deleteExclusion: (id: string) =>
    call<unknown>("/v1/exclusions/delete", { method: "POST", body: JSON.stringify({ id }) }),

  // Request a human-expert review on a finding or action (the AI + human escalation).
  requestReview: (subject: string, subjectId: string, note: string) =>
    call<ReviewRequest>("/v1/reviews", {
      method: "POST",
      body: JSON.stringify({ subject, subject_id: subjectId, note, requester: "console-user" }),
    }),

  // Returns the provider OAuth consent URL for a connector kind (the browser is then
  // 302'd to it by the /connect/[kind] route handler). Throws if the kind is unknown.
  connectURL: (kind: string) => call<{ authorize_url: string }>(`/v1/connect/${kind}`),
};

// Re-exported from the neutral module so existing server-side imports keep working while
// client components import the constants directly from "@/lib/frameworks" (this file is
// server-only and can't be pulled into a client bundle).
export { FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_CATEGORY } from "./frameworks";
