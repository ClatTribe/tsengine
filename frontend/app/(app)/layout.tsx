import Link from "next/link";
import { redirect } from "next/navigation";
import { ShieldAlert } from "lucide-react";
import { getSession } from "@/lib/auth";
import { api } from "@/lib/api";
import { riskRating, severityCounts } from "@/lib/utils";
import { Sidebar } from "@/components/shell/sidebar";
import { TopBar } from "@/components/shell/topbar";
import { CommandPalette } from "@/components/shell/command-palette";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  if (!session) redirect("/login");

  // getSession() only checks the cookie EXISTS — not that its token still authenticates. A cookie
  // can outlive its server-side session (the platform was reset/re-seeded, or the session expired),
  // in which case every authed API call silently 401s and the app renders EMPTY — no findings, no
  // account info — which reads as "my data vanished". If the token no longer resolves to a user,
  // the session is stale: send them to /login to re-authenticate instead of a hollow app. (/login
  // is outside (app), so this can't loop.)
  const me = await api.me();
  if (!me) redirect("/login");

  // An invited member with a temporary password is gated out of the app until they set their own
  // — send them to the rotation screen, which also lives outside (app) so this check can't loop.
  if (me.must_change_password) redirect("/change-password");

  const [findings, approvals, tenant, practitioners] = await Promise.all([
    api.findings(),
    api.approvals(),
    api.tenant(),
    api.practitioners(),
  ]);
  const risk = riskRating(severityCounts(findings));

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar pending={approvals.length} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          workspace={tenant?.name || session.tenant}
          risk={risk}
          serviceModel={practitioners?.service_model}
          practitioner={practitioners?.practitioners?.[0] ?? null}
        />
        {tenant?.agents_halted && (
          <Link
            href="/settings"
            className="flex items-center justify-center gap-2 border-b border-critical/30 bg-critical/5 px-6 py-2 text-xs font-medium text-critical transition hover:bg-critical/10"
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            Automation is halted — no scans or fixes are running. Resume in Settings.
          </Link>
        )}
        <main className="flex-1 overflow-y-auto px-6 py-6">
          <div className="mx-auto max-w-6xl">{children}</div>
        </main>
      </div>
      <CommandPalette />
    </div>
  );
}
