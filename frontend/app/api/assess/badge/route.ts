import { apiBase } from "@/lib/auth";

// Public proxy for the embeddable grade badge — forwards ?domain= to the platform's unauthenticated
// /v1/assess/badge and streams back the SVG. Same-origin + public so a founder can <img>-embed
// `https://<site>/api/assess/badge?domain=acme.com` on their own site/README/trust page (the viral
// loop). Caching headers from the platform are preserved.
export async function GET(req: Request) {
  const domain = new URL(req.url).searchParams.get("domain") ?? "";
  const res = await fetch(`${apiBase()}/v1/assess/badge?domain=${encodeURIComponent(domain)}`, { cache: "no-store" });
  const svg = await res.text();
  return new Response(svg, {
    status: res.status,
    headers: {
      "Content-Type": "image/svg+xml; charset=utf-8",
      "Cache-Control": res.headers.get("Cache-Control") ?? "public, max-age=21600",
    },
  });
}
