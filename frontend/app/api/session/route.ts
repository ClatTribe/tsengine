import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { apiBase, TOKEN_COOKIE, TENANT_COOKIE, sessionCookieOptions } from "@/lib/auth";

// POST { email, password } → verify with the platform's auth endpoint, then store the
// returned session token (+ tenant) in httpOnly cookies. The browser never sees the token.
export async function POST(req: Request) {
  const { email, password } = await req.json().catch(() => ({}));
  if (!email || !password) {
    return NextResponse.json({ error: "Email and password are required." }, { status: 400 });
  }
  const res = await fetch(`${apiBase()}/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "Sign-in is temporarily unavailable." }, { status: 502 });
  if (res.status === 401) return NextResponse.json({ error: "Invalid email or password." }, { status: 401 });
  if (!res.ok) return NextResponse.json({ error: `Sign-in failed (HTTP ${res.status}).` }, { status: 502 });

  const data = await res.json().catch(() => ({}));
  if (!data.token || !data.tenant) return NextResponse.json({ error: "Sign-in failed." }, { status: 502 });

  const out = NextResponse.json({ ok: true });
  const opts = sessionCookieOptions();
  out.cookies.set(TOKEN_COOKIE, data.token, opts);
  out.cookies.set(TENANT_COOKIE, data.tenant, opts);
  return out;
}

// DELETE → sign out: revoke the session server-side, then clear the cookies.
export async function DELETE() {
  const jar = await cookies();
  const token = jar.get(TOKEN_COOKIE)?.value;
  if (token) {
    await fetch(`${apiBase()}/v1/auth/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }).catch(() => {});
  }
  const res = NextResponse.json({ ok: true });
  res.cookies.delete(TOKEN_COOKIE);
  res.cookies.delete(TENANT_COOKIE);
  return res;
}
