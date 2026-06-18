import { getSession, apiBase } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Same-origin SSE proxy. The browser's EventSource can't send the bearer header, so it
// connects here (cookie auth); we resolve the session server-side and stream the upstream
// Go /v1/events feed back verbatim, with the token never reaching the browser. req.signal
// propagates the client disconnect upstream so the Go handler's request context cancels.
export async function GET(req: Request) {
  const s = await getSession();
  if (!s) return new Response("unauthorized", { status: 401 });

  const upstream = await fetch(`${apiBase()}/v1/events`, {
    headers: { Authorization: `Bearer ${s.token}`, "X-Tenant-ID": s.tenant, Accept: "text/event-stream" },
    cache: "no-store",
    signal: req.signal,
  }).catch(() => null);

  if (!upstream || !upstream.ok || !upstream.body) {
    return new Response("upstream unavailable", { status: 502 });
  }

  return new Response(upstream.body, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
