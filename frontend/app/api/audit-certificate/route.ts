import { getSession, apiBase } from "@/lib/auth";

// Proxies GET /v1/audit-review/certificate with the session's bearer token (server-side), so the
// browser downloads the signed Safe-to-Host certificate without holding the token. ?target= names the
// application; ?format=html (default, print-ready) | md; repeated ?not_tested= carries the auditor's
// own coverage limits. A refused certificate comes back as the API's 409 with the blockers — never as
// a document.
export async function GET(req: Request) {
  const s = await getSession();
  if (!s) return new Response("unauthorized", { status: 401 });
  const url = new URL(req.url);
  const target = url.searchParams.get("target");
  if (!target) return new Response("missing target", { status: 400 });
  const format = url.searchParams.get("format") === "md" ? "md" : "html";
  const q = new URLSearchParams({ target, format });
  for (const n of url.searchParams.getAll("not_tested")) q.append("not_tested", n);
  const res = await fetch(`${apiBase()}/v1/audit-review/certificate?${q.toString()}`, {
    headers: { Authorization: `Bearer ${s.token}`, "X-Tenant-ID": s.tenant },
    cache: "no-store",
  });
  const body = await res.arrayBuffer();
  const headers: Record<string, string> = {
    "Content-Type": res.headers.get("content-type") ?? (format === "md" ? "text/markdown; charset=utf-8" : "text/html; charset=utf-8"),
  };
  if (res.ok) {
    const slug = target.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "application";
    headers["Content-Disposition"] = `${format === "md" ? "attachment" : "inline"}; filename="safe-to-host-${slug}.${format}"`;
  }
  return new Response(body, { status: res.status, headers });
}
