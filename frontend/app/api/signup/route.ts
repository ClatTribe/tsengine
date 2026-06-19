import { NextResponse } from "next/server";
import { apiBase, TOKEN_COOKIE, TENANT_COOKIE, sessionCookieOptions } from "@/lib/auth";

// POST { workspace, email, password, name? } → create a workspace + its owner account on
// the platform, then sign in (store the returned session token + tenant in httpOnly cookies).
export async function POST(req: Request) {
  const { workspace, email, password, name } = await req.json().catch(() => ({}));
  if (!workspace || !email || !password) {
    return NextResponse.json({ error: "Workspace, email and password are required." }, { status: 400 });
  }
  if (String(password).length < 8) {
    return NextResponse.json({ error: "Password must be at least 8 characters." }, { status: 400 });
  }
  const res = await fetch(`${apiBase()}/v1/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ workspace, email, password, name }),
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "Sign-up is temporarily unavailable." }, { status: 502 });

  const data = await res.json().catch(() => ({}));
  if (res.status === 409) {
    return NextResponse.json({ error: data.error ?? "An account with that email already exists." }, { status: 409 });
  }
  if (!res.ok || !data.token || !data.tenant) {
    return NextResponse.json({ error: data.error ?? "Sign-up failed." }, { status: 400 });
  }

  const out = NextResponse.json({ ok: true });
  const opts = sessionCookieOptions();
  out.cookies.set(TOKEN_COOKIE, data.token, opts);
  out.cookies.set(TENANT_COOKIE, data.tenant, opts);
  return out;
}
