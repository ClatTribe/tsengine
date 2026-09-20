import { getSession, apiBase } from "@/lib/auth";

// Proxies GET /v1/jobs/{id} with the session's bearer token so the browser can POLL a background
// job — today the post-connect discover+scan the OAuth callback queues — without the token leaving
// the server. Mirrors /api/pentest-progress. ?id= selects the job; the platform scopes it to the
// session's tenant, so a foreign id is a 404 here too.
export async function GET(req: Request) {
  const s = await getSession();
  if (!s) return new Response("unauthorized", { status: 401 });
  const id = new URL(req.url).searchParams.get("id");
  if (!id) return new Response("missing id", { status: 400 });
  const res = await fetch(`${apiBase()}/v1/jobs/${encodeURIComponent(id)}`, {
    headers: { Authorization: `Bearer ${s.token}`, "X-Tenant-ID": s.tenant },
    cache: "no-store",
  });
  return new Response(await res.arrayBuffer(), {
    status: res.status,
    headers: { "Content-Type": "application/json" },
  });
}
