import "server-only";
import { getSession, apiBase, type Session } from "./auth";
import type { AIBom, Action, Asset, AttackPaths, ComplianceReport, Connection, ControlState, Engagement, ExclusionRule, Finding, Incident, IssuesResponse, PentestEngagement, PentestStats, Questionnaire, ReviewRequest, Tenant, TrustLink, User } from "./types";

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

export const api = {
  findings: () => safe<Finding[]>("/v1/findings", []),
  finding: async (id: string) => (await safe<Finding[]>("/v1/findings", [])).find((f) => f.id === id) ?? null,
  incidents: (status?: "all") => safe<Incident[]>(`/v1/incidents${status ? "?status=all" : ""}`, []),
  attackPaths: () => safe<AttackPaths>("/v1/attack-paths", { attack_paths: [], count: 0 }),
  issues: (showIgnored?: boolean) =>
    safe<IssuesResponse>(`/v1/issues${showIgnored ? "?show=ignored" : ""}`, { issues: [], count: 0, raw_findings: 0, confirmed: 0, ignored: 0 }),
  pentests: () => safe<PentestEngagement[]>("/v1/pentest", []),
  pentest: (id: string) => safe<PentestEngagement | null>(`/v1/pentest/${id}`, null),
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
