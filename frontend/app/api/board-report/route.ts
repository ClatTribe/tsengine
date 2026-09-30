import { getSession, apiBase } from "@/lib/auth";

// Proxies GET /v1/board-report?format=md with the session token, so the browser downloads the
// one-page board report without holding the bearer token.
export async function GET() {
  const s = await getSession();
  if (!s) return new Response("unauthorized", { status: 401 });
  const res = await fetch(`${apiBase()}/v1/board-report?format=md`, {
    headers: { Authorization: `Bearer ${s.token}`, "X-Tenant-ID": s.tenant },
    cache: "no-store",
  });
  return new Response(await res.arrayBuffer(), {
    status: res.status,
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "Content-Disposition": 'attachment; filename="security-board-report.md"',
    },
  });
}
