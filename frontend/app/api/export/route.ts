import { getSession, apiBase } from "@/lib/auth";

// Proxies GET /v1/findings/export with the session's bearer token (server-side), so the
// browser can download SARIF/CSV without ever holding the token.
export async function GET(req: Request) {
  const s = await getSession();
  if (!s) return new Response("unauthorized", { status: 401 });
  const fmt = new URL(req.url).searchParams.get("format") === "csv" ? "csv" : "sarif";
  const res = await fetch(`${apiBase()}/v1/findings/export?format=${fmt}`, {
    headers: { Authorization: `Bearer ${s.token}`, "X-Tenant-ID": s.tenant },
    cache: "no-store",
  });
  const body = await res.arrayBuffer();
  return new Response(body, {
    status: res.status,
    headers: {
      "Content-Type": res.headers.get("content-type") ?? "application/octet-stream",
      "Content-Disposition": res.headers.get("content-disposition") ?? `attachment; filename="findings.${fmt}"`,
    },
  });
}
