import "server-only";
import { cookies } from "next/headers";
import { apiBase, sessionCookieOptions } from "./auth";

// Operator auth — a DELIBERATELY SEPARATE surface from the tenant session (lib/auth.ts). An operator
// is a cross-tenant practitioner (the MSP's expert or our managed delivery expert). Their token lives
// in its own httpOnly cookie and carries NO tenant header — the operator endpoints are tenant-agnostic
// and scope themselves to the operator's assigned tenants server-side. So this never touches tenant
// isolation.

export const OP_TOKEN_COOKIE = "op_token";

export interface Operator {
  id: string;
  email: string;
  name?: string;
  firm?: string;
}

export interface QueueItem {
  tenant_id: string;
  tenant_name: string;
  kind: string; // risk | audit | pentest | policy
  item_id: string; // the underlying entity id — for act-on-behalf
  controls?: string[]; // for audits: the control ids still awaiting attestation
  title: string;
  detail?: string;
  link: string;
}

export interface OperatorQueue {
  practitioner: string;
  tenants_served: number;
  count: number;
  by_kind: Record<string, number>;
  items: QueueItem[];
}

export async function getOperatorToken(): Promise<string | null> {
  const jar = await cookies();
  return jar.get(OP_TOKEN_COOKIE)?.value ?? null;
}

// operatorFetch calls an operator endpoint with the operator bearer token. Returns null when there is
// no session or the call fails (the page redirects to /operator/login on null).
async function operatorFetch<T>(path: string): Promise<T | null> {
  const tok = await getOperatorToken();
  if (!tok) return null;
  const res = await fetch(apiBase() + path, {
    headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
    cache: "no-store",
  });
  if (!res.ok) return null;
  return (await res.json()) as T;
}

export function operatorMe(): Promise<Operator | null> {
  return operatorFetch<Operator>("/v1/operator/me");
}

export function operatorQueue(): Promise<OperatorQueue | null> {
  return operatorFetch<OperatorQueue>("/v1/operator/queue");
}

// operatorCookieOptions reuses the tenant cookie hardening (httpOnly + SameSite=Strict + secure).
export const operatorCookieOptions = sessionCookieOptions;
