import { NextResponse } from "next/server";
import { apiBase, TOKEN_COOKIE, TENANT_COOKIE } from "@/lib/auth";

// POST { token, tenant } → validate against the Go API, then set httpOnly cookies.
export async function POST(req: Request) {
  const { token, tenant } = await req.json().catch(() => ({}));
  if (!token || !tenant) {
    return NextResponse.json({ error: "token and tenant are required" }, { status: 400 });
  }
  // Validate the credentials by making one authed call before persisting them.
  const probe = await fetch(`${apiBase()}/v1/approvals`, {
    headers: { Authorization: `Bearer ${token}`, "X-Tenant-ID": tenant },
    cache: "no-store",
  }).catch(() => null);
  if (!probe || probe.status === 401) {
    return NextResponse.json({ error: "Invalid token or tenant." }, { status: 401 });
  }
  if (!probe.ok && probe.status !== 200) {
    return NextResponse.json({ error: `API unreachable (HTTP ${probe.status}).` }, { status: 502 });
  }
  const res = NextResponse.json({ ok: true });
  const secure = process.env.NODE_ENV === "production";
  const opts = { httpOnly: true, sameSite: "strict" as const, secure, path: "/" };
  res.cookies.set(TOKEN_COOKIE, token, opts);
  res.cookies.set(TENANT_COOKIE, tenant, opts);
  return res;
}

// DELETE → sign out.
export async function DELETE() {
  const res = NextResponse.json({ ok: true });
  res.cookies.delete(TOKEN_COOKIE);
  res.cookies.delete(TENANT_COOKIE);
  return res;
}
