import "server-only";
import { getSession, apiBase, type Session } from "./auth";
import type { Action, Connection, ControlState, Engagement, Finding, Incident } from "./types";

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

/** Like call() but never throws — returns a fallback. For non-critical dashboard widgets. */
async function safe<T>(path: string, fallback: T): Promise<T> {
  try {
    return await call<T>(path);
  } catch {
    return fallback;
  }
}

export const api = {
  findings: () => safe<Finding[]>("/v1/findings", []),
  incidents: (status?: "all") => safe<Incident[]>(`/v1/incidents${status ? "?status=all" : ""}`, []),
  approvals: () => safe<Action[]>("/v1/approvals", []),
  connections: () => safe<Connection[]>("/v1/connections", []),
  engagements: () => safe<Engagement[]>("/v1/engagements", []),
  posture: (framework: string) => safe<ControlState[]>(`/v1/posture/${framework}`, []),

  // writes (Server Actions call these)
  decide: (id: string, approve: boolean, approver: string) =>
    call<Action>(`/v1/approvals/${id}`, {
      method: "POST",
      body: JSON.stringify({ approver, approve }),
    }),
  rescan: () => call<{ assets_scanned: number }>("/v1/rescan", { method: "POST" }),
};

export const FRAMEWORKS = ["soc2", "iso27001", "pci", "hipaa", "cis_v8", "nist_csf"] as const;
export const FRAMEWORK_LABEL: Record<string, string> = {
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  pci: "PCI-DSS",
  hipaa: "HIPAA",
  cis_v8: "CIS v8",
  nist_csf: "NIST CSF",
};
