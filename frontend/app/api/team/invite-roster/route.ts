import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { apiBase, TOKEN_COOKIE } from "@/lib/auth";

// GET  → who the HRIS roster would seat as employees, without seating anyone (owner-only, platform-enforced).
// POST → seat them. Returns invited/already_seated/skipped/failed, each NAMED; temp passwords ride
//        back only for people the platform could not email.
async function forward(method: "GET" | "POST") {
  const jar = await cookies();
  const token = jar.get(TOKEN_COOKIE)?.value;
  if (!token) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const res = await fetch(`${apiBase()}/v1/auth/invite-roster`, {
    method,
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "The roster invite is temporarily unavailable." }, { status: 502 });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) return NextResponse.json({ error: data.error ?? "Roster invite failed.", code: data.code }, { status: res.status });
  return NextResponse.json(data);
}

export async function GET() {
  return forward("GET");
}

export async function POST() {
  return forward("POST");
}
