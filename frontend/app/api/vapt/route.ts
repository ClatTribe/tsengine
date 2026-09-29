import { getSession, apiBase } from "@/lib/auth";

// Proxies GET /v1/vapt/report (the customer-facing VAPT / pentest deliverable) with the session
// token, so the browser fetches it without holding the bearer token.
//
// ?format=html serves the print-ready document the customer saves as PDF — opened in a tab
// (inline) rather than downloaded, because the whole point is to reach the browser's print
// dialog. Markdown stays the default and stays an attachment (the developer deliverable).
export async function GET(req: Request) {
  const s = await getSession();
  if (!s) return new Response("unauthorized", { status: 401 });

  const params = new URL(req.url).searchParams;
  const html = params.get("format") === "html";
  // ?product=<id> scopes the report to one CONFIRMED product (ADR 0028 G2). Forwarded as-is, encoded;
  // the API 404s an unknown or foreign id rather than silently falling back to the whole workspace.
  const product = params.get("product");
  const scope = product ? `&product=${encodeURIComponent(product)}` : "";
  const res = await fetch(`${apiBase()}/v1/vapt/report?format=${html ? "html" : "md"}${scope}`, {
    headers: { Authorization: `Bearer ${s.token}`, "X-Tenant-ID": s.tenant },
    cache: "no-store",
  });
  const body = await res.arrayBuffer();
  return new Response(body, {
    status: res.status,
    headers: html
      ? { "Content-Type": "text/html; charset=utf-8", "Content-Disposition": "inline" }
      : {
          "Content-Type": "text/markdown; charset=utf-8",
          "Content-Disposition": `attachment; filename="${product ? "vapt-report-product.md" : "vapt-report.md"}"`,
        },
  });
}
