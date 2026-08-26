import { apiBase } from "@/lib/auth";

// Public proxy for the Trust Center's buyer-facing endpoints. No session: these are the
// endpoints a prospect hits, and the platform gates them on the share token in the query
// string rather than on who is logged in.
//
// The proxy exists because the platform API is not necessarily reachable from a browser —
// same reason /api/questionnaire exists — and because it keeps the platform's address out of
// the public page's markup.
//
// Only the three buyer actions are routed. An open-ended proxy on a PUBLIC path would let
// anyone reach any platform endpoint from the internet with whatever query string they liked,
// so the allow-list is the security boundary here, not a tidiness measure.
const POSTABLE = new Set(["request", "nda"]);

export async function POST(req: Request, ctx: { params: Promise<{ tenant: string; action: string }> }) {
  const { tenant, action } = await ctx.params;
  if (!POSTABLE.has(action)) return new Response("not found", { status: 404 });

  const url = new URL(req.url);
  const target = `${apiBase()}/v1/trust/${encodeURIComponent(tenant)}/${action}${url.search}`;
  const res = await fetch(target, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: await req.text(),
    cache: "no-store",
  });
  return new Response(await res.text(), {
    status: res.status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function GET(req: Request, ctx: { params: Promise<{ tenant: string; action: string }> }) {
  const { tenant, action } = await ctx.params;
  if (action !== "doc") return new Response("not found", { status: 404 });

  const url = new URL(req.url);
  const target = `${apiBase()}/v1/trust/${encodeURIComponent(tenant)}/doc${url.search}`;
  // An external document answers 302 to wherever the tenant hosts it. Following it here would
  // stream someone else's file through our origin, so the redirect is passed back for the
  // browser to follow — the reader can then see in their address bar whose server they are on.
  const res = await fetch(target, { cache: "no-store", redirect: "manual" });
  const location = res.headers.get("location");
  if (location && res.status >= 300 && res.status < 400) {
    return new Response(null, { status: 302, headers: { Location: location } });
  }
  const body = await res.text();
  if (!res.ok) return new Response(body, { status: res.status, headers: { "Content-Type": "application/json" } });
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "Content-Disposition": res.headers.get("content-disposition") ?? "inline",
    },
  });
}
