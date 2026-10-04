import { NextResponse } from "next/server";
import { apiBase } from "@/lib/auth";

// POST { email } → ask the platform whether this person signs in through SSO, and where to send them.
// The answer says only whether SSO applies; it never reveals whether an account exists.
export async function POST(req: Request) {
  const { email } = await req.json().catch(() => ({}));
  if (!email) return NextResponse.json({ error: "Enter your work email." }, { status: 400 });
  const res = await fetch(`${apiBase()}/v1/auth/sso/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "Sign-in is temporarily unavailable." }, { status: 502 });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return NextResponse.json({ error: data.error ?? "Single sign-on is unavailable right now." }, { status: 502 });
  return NextResponse.json({ sso: !!data.sso, authorize_url: data.authorize_url });
}
