import { apiBase } from "@/lib/auth";

// Public proxy for the book-a-demo / talk-to-sales lead form — forwards to the platform's
// unauthenticated POST /v1/lead (no session needed). Same-origin so the browser never talks to
// the API host directly.
export async function POST(req: Request) {
  const body = await req.text();
  const res = await fetch(`${apiBase()}/v1/lead`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
    cache: "no-store",
  });
  const out = await res.text();
  return new Response(out, { status: res.status, headers: { "Content-Type": "application/json" } });
}
