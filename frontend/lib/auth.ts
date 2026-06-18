import { cookies } from "next/headers";

// Auth model: the browser never holds the platform token. Login stores it (+ the tenant)
// in httpOnly cookies; Server Components / Actions read them here and call the Go API
// server-side. SameSite=Strict + httpOnly = no token in JS, no CSRF on the cross-site path.

export const TOKEN_COOKIE = "ts_token";
export const TENANT_COOKIE = "ts_tenant";

export interface Session {
  token: string;
  tenant: string;
}

/** Returns the current session from cookies, or null when unauthenticated. */
export async function getSession(): Promise<Session | null> {
  const jar = await cookies();
  const token = jar.get(TOKEN_COOKIE)?.value;
  const tenant = jar.get(TENANT_COOKIE)?.value;
  if (!token || !tenant) return null;
  return { token, tenant };
}

/** The API base — server-side only (never shipped to the browser). */
export function apiBase(): string {
  return process.env.TSENGINE_API_URL ?? "http://localhost:8090";
}
