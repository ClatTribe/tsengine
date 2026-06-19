import { apiBase } from "@/lib/auth";

// Public proxy for the instant assessment — forwards ?domain= to the platform's unauthenticated
// /v1/assess (no session needed; this is the top-of-funnel lead magnet). Same-origin so the
// browser never talks to the API host directly.
export async function GET(req: Request) {
  const domain = new URL(req.url).searchParams.get("domain") ?? "";
  const res = await fetch(`${apiBase()}/v1/assess?domain=${encodeURIComponent(domain)}`, { cache: "no-store" });
  const body = await res.text();
  return new Response(body, { status: res.status, headers: { "Content-Type": "application/json" } });
}
