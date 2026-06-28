"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { LogOut, Search, Settings, Building2, UserCog } from "lucide-react";
import { RiskPill } from "@/components/ui/primitives";
import { LiveStatus } from "@/components/shell/live-status";
import { ThemeToggle } from "@/components/theme-toggle";

// Who runs the security & compliance work — the ONE thing that differs across the three GTM models
// (§18.5). A standing indicator so a managed/MSP customer always sees "an expert runs this for you".
const SERVICE_LABEL: Record<string, string> = {
  self_serve: "Self-managed",
  msp: "Partner-managed",
  managed: "Managed service",
};

export function TopBar({
  workspace,
  risk,
  serviceModel,
  practitioner,
}: {
  workspace: string;
  risk: string;
  serviceModel?: string;
  practitioner?: { name?: string; firm?: string } | null;
}) {
  const router = useRouter();
  async function signOut() {
    await fetch("/api/session", { method: "DELETE" });
    router.push("/login");
    router.refresh();
  }
  const svcLabel = serviceModel ? SERVICE_LABEL[serviceModel] : undefined;
  const who = practitioner?.firm || practitioner?.name;
  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border px-5">
      {/* the workspace name — a founder should see "Acme", never a raw tenant id */}
      <div className="flex items-center gap-2 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm font-medium">
        <Building2 className="h-3.5 w-3.5 text-faint" />
        <span className="max-w-[14rem] truncate">{workspace}</span>
      </div>

      {/* Service model — who employs the human-in-the-loop (self-serve / MSP / managed). Links to the
          "Your security team" page: who your expert(s) of record are + what they handle. */}
      {svcLabel && (
        <Link
          href="/security-team"
          title="Your security team — who runs your security & compliance and what they handle"
          className="hidden items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-muted transition hover:border-border-strong hover:text-ink md:flex"
        >
          <UserCog className="h-3.5 w-3.5 text-faint" />
          <span className="max-w-[16rem] truncate">
            {svcLabel}
            {who ? ` · ${who}` : ""}
          </span>
        </Link>
      )}

      <button
        onClick={() => window.dispatchEvent(new Event("cmdk:open"))}
        className="ml-2 flex items-center gap-2 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-muted transition hover:border-border-strong hover:text-ink"
        title="Command palette — ⌘K"
      >
        <Search className="h-3.5 w-3.5" />
        <span>Search…</span>
        <kbd className="mono rounded border border-border bg-bg px-1 text-[10px]">⌘K</kbd>
      </button>

      <div className="ml-auto flex items-center gap-3">
        <LiveStatus />
        <RiskPill rating={risk} />
        <ThemeToggle className="h-8 w-8" />
        <Link href="/settings" className="rounded-lg p-2 text-muted transition hover:bg-surface hover:text-ink" title="Settings">
          <Settings className="h-4 w-4" />
        </Link>
        <button onClick={signOut} className="rounded-lg p-2 text-muted transition hover:bg-surface hover:text-ink" title="Sign out">
          <LogOut className="h-4 w-4" />
        </button>
      </div>
    </header>
  );
}
