import { redirect } from "next/navigation";
import { getSession } from "@/lib/auth";
import { api } from "@/lib/api";
import { riskRating, severityCounts } from "@/lib/utils";
import { Sidebar } from "@/components/shell/sidebar";
import { TopBar } from "@/components/shell/topbar";
import { CommandPalette } from "@/components/shell/command-palette";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  if (!session) redirect("/login");

  const [findings, approvals] = await Promise.all([api.findings(), api.approvals()]);
  const risk = riskRating(severityCounts(findings));

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar pending={approvals.length} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar tenant={session.tenant} risk={risk} />
        <main className="flex-1 overflow-y-auto px-6 py-6">
          <div className="mx-auto max-w-6xl">{children}</div>
        </main>
      </div>
      <CommandPalette />
    </div>
  );
}
