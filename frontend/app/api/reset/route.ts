import { NextResponse } from "next/server";
import { apiBase } from "@/lib/auth";

// POST { email, token, new_password } → complete a password reset against the platform.
export async function POST(req: Request) {
  const { email, token, new_password } = await req.json().catch(() => ({}));
  if (!email || !token || !new_password) {
    return NextResponse.json({ error: "Missing reset details." }, { status: 400 });
  }
  if (String(new_password).length < 8) {
    return NextResponse.json({ error: "Password must be at least 8 characters." }, { status: 400 });
  }
  const res = await fetch(`${apiBase()}/v1/auth/reset`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, token, new_password }),
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "Service temporarily unavailable." }, { status: 502 });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return NextResponse.json({ error: data.error ?? "This reset link is invalid or has expired." }, { status: res.status });
  }
  return NextResponse.json({ ok: true, message: data.message ?? "Your password has been reset." });
}
