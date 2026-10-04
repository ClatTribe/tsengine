import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { apiBase, TOKEN_COOKIE, TENANT_COOKIE, MFA_COOKIE, sessionCookieOptions } from "@/lib/auth";

// POST { code } or { recovery_code } → redeem the second-factor challenge held in the httpOnly MFA
// cookie. On success the real session cookies are set and the challenge cookie is cleared.
export async function POST(req: Request) {
  const { code, recovery_code } = await req.json().catch(() => ({}));
  const jar = await cookies();
  const challenge = jar.get(MFA_COOKIE)?.value;
  if (!challenge) {
    return NextResponse.json(
      { error: "This sign-in has expired — enter your email and password again.", expired: true },
      { status: 401 },
    );
  }
  const res = await fetch(`${apiBase()}/v1/auth/2fa/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge, code: code ?? "", recovery_code: recovery_code ?? "" }),
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "Sign-in is temporarily unavailable." }, { status: 502 });
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    // An expired or burned challenge cannot be retried — send the person back to the password step
    // rather than letting them type codes into a sign-in that no longer exists.
    const dead = data.code === "two_factor_expired" || data.code === "two_factor_locked";
    const out = NextResponse.json({ error: data.error ?? "That code is not right.", expired: dead }, { status: 401 });
    if (dead) out.cookies.delete(MFA_COOKIE);
    return out;
  }
  if (!data.token || !data.tenant) return NextResponse.json({ error: "Sign-in failed." }, { status: 502 });

  const out = NextResponse.json({ ok: true, recovery_codes_remaining: data.recovery_codes_remaining });
  const opts = sessionCookieOptions();
  out.cookies.set(TOKEN_COOKIE, data.token, opts);
  out.cookies.set(TENANT_COOKIE, data.tenant, opts);
  out.cookies.delete(MFA_COOKIE);
  return out;
}
