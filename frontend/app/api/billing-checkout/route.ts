import { getSession, apiBase } from "@/lib/auth";
import { NextResponse } from "next/server";

// Proxies POST /v1/billing/checkout with the session's bearer token (server-side), so the browser
// starts a real Razorpay order without ever holding the platform token. Returns { order_id, key_id,
// amounts, descriptor } — key_id is Razorpay's PUBLIC key, which the checkout modal needs; the key
// SECRET never leaves the platform.
export async function POST(req: Request) {
  const s = await getSession();
  if (!s) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  const res = await fetch(`${apiBase()}/v1/billing/checkout`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${s.token}`,
      "X-Tenant-ID": s.tenant,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ plan: body?.plan ?? "growth", cycle: body?.cycle ?? "monthly" }),
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "Checkout is temporarily unavailable." }, { status: 502 });
  const data = await res.json().catch(() => ({}));
  return NextResponse.json(data, { status: res.status });
}
