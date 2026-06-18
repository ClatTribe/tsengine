"use client";

import { useRouter } from "next/navigation";
import { LogOut, Search } from "lucide-react";
import { RiskPill } from "@/components/ui/primitives";

export function TopBar({ tenant, risk }: { tenant: string; risk: string }) {
  const router = useRouter();
  async function signOut() {
    await fetch("/api/session", { method: "DELETE" });
    router.push("/login");
    router.refresh();
  }
  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border px-5">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted">tenant</span>
        <span className="mono rounded-md border border-border bg-surface px-2 py-0.5">{tenant}</span>
      </div>

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
        <RiskPill rating={risk} />
        <button onClick={signOut} className="rounded-lg p-2 text-muted transition hover:bg-surface hover:text-ink" title="Sign out">
          <LogOut className="h-4 w-4" />
        </button>
      </div>
    </header>
  );
}
