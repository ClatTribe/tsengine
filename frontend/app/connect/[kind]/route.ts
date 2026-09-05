import { NextResponse } from "next/server";
import { api, ApiError } from "@/lib/api";
import { getSession } from "@/lib/auth";

// Browser navigates here to start connecting a system. We resolve the provider's OAuth
// consent URL server-side (the session token never reaches the browser) and 302 the user
// into the provider's consent screen. The provider then redirects back to the Go API's
// /v1/connect/{kind}/callback, which discovers + scans the new assets.
export async function GET(_req: Request, ctx: { params: Promise<{ kind: string }> }) {
  const { kind } = await ctx.params;
  const s = await getSession();
  if (!s) return NextResponse.redirect(new URL("/login", _req.url));
  try {
    const { authorize_url } = await api.connectURL(kind);
        // Grant-based providers (GCP) have no OAuth redirect-back: route them to a setup page that
    // shows the grant link + collects the project id, instead of a dead-end redirect to the console.
    if (kind === "gcp" || kind === "aws") {
      const setup = new URL(`/connect-setup/${kind}`, _req.url);
      setup.searchParams.set("u", authorize_url);
      return NextResponse.redirect(setup);
    }
    return NextResponse.redirect(authorize_url);
  } catch (e) {
    const status = e instanceof ApiError ? e.status : 502;
    // Unknown kind or the connector isn't configured on this deployment → back to Assets
    // with an error flag the page can surface.
    return NextResponse.redirect(new URL(`/assets?connect_error=${encodeURIComponent(kind)}&code=${status}`, _req.url));
  }
}
