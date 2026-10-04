import { NextResponse } from "next/server";
import { apiBase, TOKEN_COOKIE, TENANT_COOKIE, MFA_COOKIE, sessionCookieOptions } from "@/lib/auth";

// The identity provider sends the browser back here with ?code&state. The platform exchanges the code
// and verifies the ID token; on success the session lands in the same httpOnly cookies a password
// sign-in uses. Every outcome ends on a page that says what happened — never a blank callback URL.
export async function GET(req: Request) {
  const u = new URL(req.url);
  const back = (q: string) => NextResponse.redirect(new URL(`/login?${q}`, u.origin));
  const idpError = u.searchParams.get("error_description") ?? u.searchParams.get("error");
  if (idpError) return back(`sso_error=${encodeURIComponent(`Your identity provider stopped the sign-in: ${idpError}`)}`);
  const code = u.searchParams.get("code");
  const state = u.searchParams.get("state");
  if (!code || !state) return back(`sso_error=${encodeURIComponent("The sign-in came back incomplete — start again.")}`);

  const res = await fetch(`${apiBase()}/v1/auth/sso/callback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, state }),
    cache: "no-store",
  }).catch(() => null);
  if (!res) return back(`sso_error=${encodeURIComponent("Sign-in is temporarily unavailable.")}`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return back(`sso_error=${encodeURIComponent(data.error ?? "Single sign-on failed.")}`);

  // The person has their own authenticator and the provider did not assert a second factor: ask for it.
  if (data.two_factor_required && data.challenge) {
    const out = back("step=code");
    out.cookies.set(MFA_COOKIE, data.challenge, { ...sessionCookieOptions(), maxAge: 5 * 60 });
    return out;
  }
  if (!data.token || !data.tenant) return back(`sso_error=${encodeURIComponent("Single sign-on failed.")}`);
  const out = NextResponse.redirect(new URL("/dashboard", u.origin));
  const opts = sessionCookieOptions();
  out.cookies.set(TOKEN_COOKIE, data.token, opts);
  out.cookies.set(TENANT_COOKIE, data.tenant, opts);
  return out;
}
