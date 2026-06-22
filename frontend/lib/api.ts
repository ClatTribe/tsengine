import "server-only";
import { getSession, apiBase, type Session } from "./auth";
import type { AIBom, Action, Asset, AttackPaths, ComplianceReport, Connection, ControlState, Engagement, ExclusionRule, Finding, Incident, IssuesResponse, PentestEngagement, PentestStats, PostureSummary, PRBotSettings, Questionnaire, ReviewRequest, SaaSAppsResponse, Tenant, TrustLink, User } from "./types";

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
  attackPaths: () => safe<AttackPaths>("/v1/attack-paths", { attack_paths: [], count: 0 }),

  // SaaS-app discovery view (SSPM) — inventory + portfolio summary over the connected IdPs' grants.
  saasApps: () =>
    safe<SaaSAppsResponse>("/v1/saas-apps", {
      apps: [],
      summary: { total_apps: 0, sensitive_apps: 0, unverified_apps: 0, shadow_it_apps: 0, multi_user_apps: 0 },
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

  // Create + authorize a pentest engagement (the API enforces the active-mode
  // authorization gate; an unauthorized active engagement / empty scope → 400).
  createPentest: (body: {
    name: string;
    mode: string;
    rules_of_engagement: { authorized_targets: string[]; max_requests: number; allow_active?: boolean; authorized_by?: string; consent?: string };
  }) => call<PentestEngagement>("/v1/pentest", { method: "POST", body: JSON.stringify(body) }),
  runPentest: (id: string) => call<PentestEngagement>(`/v1/pentest/${id}/run`, { method: "POST" }),

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
