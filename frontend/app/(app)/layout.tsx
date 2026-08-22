import Link from "next/link";
import { redirect } from "next/navigation";
import { getSession } from "@/lib/auth";
import { api } from "@/lib/api";
import { riskRating } from "@/lib/utils";
import { DegradationBar } from "@/components/shell/degradation-bar";
import { Sidebar } from "@/components/shell/sidebar";
import { MobileNavProvider, MobileNavBackdrop } from "@/components/shell/mobile-nav";
import { TopBar } from "@/components/shell/topbar";
import { CommandPalette } from "@/components/shell/command-palette";
import { hitlOwner } from "@/lib/service-model";

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

  // Severity COUNTS, not every finding. The shell renders on every navigation and needs one number;
  // pulling the full list cost 27MB per page load for a workspace that imported a 50,000-finding
  // scanner backlog, which made importing your own data a punishment.
  const [summary, approvals, tenant, practitioners, llm, ai, system] = await Promise.all([
    api.findingsSummary(),
    api.approvals(),
    api.tenant(),
    api.practitioners(),
    api.llmSettings(),
    api.aiMode(),
    api.systemState(),
  ]);
  const risk = riskRating(summary.severity);
  // Service model: a managed/MSP customer's expert owns the HITL acts, so the pending badge is
  // informational, not the founder's accent to-do.
  const { selfOwned } = hitlOwner(practitioners?.service_model, practitioners?.practitioners?.[0]);

  return (
    <MobileNavProvider>
    <div className="flex h-screen overflow-hidden">
      <MobileNavBackdrop />
      <Sidebar
        pending={approvals.length}
        selfOwned={selfOwned}
        halted={!!tenant?.agents_halted}
        aiEnabled={!!llm.ai_enabled}
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          workspace={tenant?.name || session.tenant}
          risk={risk}
          serviceModel={practitioners?.service_model}
          practitioner={practitioners?.practitioners?.[0] ?? null}
        />
        {/* Every reason this view may be incomplete, computed server-side and rendered as a set.
            This replaced two banners that each had to be remembered separately — the arrangement that
            let a halted workspace read "agent online" and a failed scan render as an empty list. */}
        <DegradationBar degradations={system.degradations} />
        {/* px-4 below md: 24px of gutter either side is a tenth of a 375px screen. */}
        <main className="flex-1 overflow-y-auto px-4 py-5 md:px-6 md:py-6">
          <div className="mx-auto max-w-6xl">{children}</div>
        </main>
      </div>
      <CommandPalette />
    </div>
    </MobileNavProvider>
  );
}
