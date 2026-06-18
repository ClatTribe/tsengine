import { getSession, apiBase } from "@/lib/auth";

// Proxies GET /v1/compliance/{framework}/report (Markdown) with the session token, so the
// browser downloads the signed auditor report without holding the bearer token.
export async function GET(req: Request) {
  const s = await getSession();
  if (!s) return new Response("unauthorized", { status: 401 });
  const framework = new URL(req.url).searchParams.get("framework") ?? "";
  if (!/^[a-z0-9_]+$/.test(framework)) return new Response("bad framework", { status: 400 });
  const res = await fetch(`${apiBase()}/v1/compliance/${framework}/report`, {
    headers: { Authorization: `Bearer ${s.token}`, "X-Tenant-ID": s.tenant },
    cache: "no-store",
  });
  const body = await res.arrayBuffer();
  return new Response(body, {
    status: res.status,
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "Content-Disposition": `attachment; filename="${framework}-compliance.md"`,
    },
  });
}
