import { NextResponse } from "next/server";
import { getSession, apiBase } from "@/lib/auth";

// POST → grade the workspace's OWN model against its OWN graded cases.
//
// Proxied rather than called from the browser so the session token never leaves the server, and a
// POST rather than a GET because each run spends a model call per case on the customer's key. That
// is also why nothing here is prefetched or revalidated on render: this happens when a person asks.
export async function POST() {
  const s = await getSession();
  if (!s) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const res = await fetch(`${apiBase()}/v1/eval/model`, {
    method: "POST",
    headers: { Authorization: `Bearer ${s.token}`, "X-Tenant-ID": s.tenant },
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "Grading is temporarily unavailable." }, { status: 502 });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return NextResponse.json({ error: data.error ?? "Could not grade your model." }, { status: res.status });
  }
  return NextResponse.json(data);
}
