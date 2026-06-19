import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { apiBase, TOKEN_COOKIE } from "@/lib/auth";

// POST { email, name? } → invite a teammate (owner-only, enforced by the platform). Returns
// { user, temp_password } so the owner can share the one-time password out-of-band.
export async function POST(req: Request) {
  const jar = await cookies();
  const token = jar.get(TOKEN_COOKIE)?.value;
  if (!token) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const { email, name } = await req.json().catch(() => ({}));
  if (!email) return NextResponse.json({ error: "Email is required." }, { status: 400 });

  const res = await fetch(`${apiBase()}/v1/auth/invite`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email, name }),
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "Invite is temporarily unavailable." }, { status: 502 });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) return NextResponse.json({ error: data.error ?? "Invite failed." }, { status: res.status });
  return NextResponse.json(data);
}
