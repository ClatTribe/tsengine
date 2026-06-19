import { getSession, apiBase } from "@/lib/auth";

// Proxies GET /v1/vapt/report?format=md (the customer-facing VAPT / pentest deliverable)
// with the session token, so the browser downloads it without holding the bearer token.
export async function GET() {
  const s = await getSession();
  if (!s) return new Response("unauthorized", { status: 401 });
  const res = await fetch(`${apiBase()}/v1/vapt/report?format=md`, {
    headers: { Authorization: `Bearer ${s.token}`, "X-Tenant-ID": s.tenant },
    cache: "no-store",
  });
  const body = await res.arrayBuffer();
  return new Response(body, {
    status: res.status,
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "Content-Disposition": `attachment; filename="vapt-report.md"`,
    },
  });
}
