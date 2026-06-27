import { NextResponse } from "next/server";
import { apiBase } from "@/lib/auth";

// POST { email } → ask the platform to start a password reset. The platform always responds
// the same way (no account enumeration) and emails a one-time link if the account exists.
export async function POST(req: Request) {
  const { email } = await req.json().catch(() => ({}));
  if (!email) {
    return NextResponse.json({ error: "Email is required." }, { status: 400 });
  }
  const res = await fetch(`${apiBase()}/v1/auth/forgot`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "Service temporarily unavailable." }, { status: 502 });
  const data = await res.json().catch(() => ({}));
  return NextResponse.json({ ok: true, message: data.message ?? "If an account exists, a reset link is on its way." });
}
