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

  // An invited member with a temporary password is gated out of the app (the API returns
  // 403 password_change_required) until they set their own — send them to the rotation
  // screen, which lives outside (app) so this check can't loop.
  const me = await api.me();
  if (me?.must_change_password) redirect("/change-password");

  const [findings, approvals, tenant] = await Promise.all([api.findings(), api.approvals(), api.tenant()]);
  const risk = riskRating(severityCounts(findings));

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar pending={approvals.length} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar tenant={session.tenant} risk={risk} />
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
