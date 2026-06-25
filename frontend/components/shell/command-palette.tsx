"use client";

import { useEffect, useMemo, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  LayoutDashboard, Inbox, Bug, Activity, ShieldCheck, Boxes, ScrollText,
  RefreshCw, Plug, LogOut, Search, CornerDownLeft, Settings, FileText, UserCheck,
} from "lucide-react";
import { rescanAll } from "@/app/(app)/assets/actions";
import { FRAMEWORKS, FRAMEWORK_LABEL } from "@/lib/frameworks";
import { cn } from "@/lib/utils";

// The global ⌘K command palette. Opens on ⌘K / Ctrl-K, or via the topbar button
// (which dispatches `cmdk:open`). Keyboard-first: type to filter, ↑↓ to move, Enter to
// run, Esc to close. Commands are nav jumps + the handful of real actions (scan, connect,
// sign out, compliance quick-jump). Lives once, mounted in the authed layout.

type Cmd = {
  id: string;
  label: string;
  group: "Go to" | "Actions" | "Compliance";
  icon: typeof Search;
  keywords?: string;
  run: () => void;
};

export function CommandPalette() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [, startScan] = useTransition();
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const close = () => { setOpen(false); setQ(""); setSel(0); };

  // open triggers: ⌘K / Ctrl-K globally + the topbar button's custom event
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    const onOpen = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener("cmdk:open", onOpen);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("cmdk:open", onOpen);
    };
  }, []);

  useEffect(() => {
    if (open) requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  const commands = useMemo<Cmd[]>(() => {
    const go = (href: string) => () => { close(); router.push(href); };
    const nav: Cmd[] = [
      { id: "overview", label: "Overview", group: "Go to", icon: LayoutDashboard, keywords: "home dashboard risk", run: go("/dashboard") },
      { id: "inbox", label: "Inbox", group: "Go to", icon: Inbox, keywords: "approvals hitl triage", run: go("/inbox") },
      { id: "reviews", label: "Expert reviews", group: "Go to", icon: UserCheck, keywords: "human expert escalation second opinion vciso", run: go("/reviews") },
      { id: "findings", label: "Findings", group: "Go to", icon: Bug, keywords: "vulnerabilities issues", run: go("/findings") },
      { id: "incidents", label: "Incidents", group: "Go to", icon: Activity, keywords: "monitoring new resolved", run: go("/incidents") },
      { id: "compliance", label: "Compliance", group: "Go to", icon: ShieldCheck, keywords: "soc2 controls audit posture", run: go("/compliance") },
      { id: "risks", label: "Risk register", group: "Go to", icon: ShieldCheck, keywords: "vciso risk accept treat mitigate likelihood impact judgment", run: go("/risks") },
      { id: "audits", label: "Audits", group: "Go to", icon: FileText, keywords: "soc2 iso audit engagement auditor attestation external", run: go("/audits") },
      { id: "questionnaire", label: "Security questionnaire", group: "Go to", icon: ShieldCheck, keywords: "caiq sig vendor trust center procurement", run: go("/compliance/questionnaire") },
      { id: "reports", label: "Reports & evidence", group: "Go to", icon: FileText, keywords: "export sarif csv evidence pack signed download auditor", run: go("/reports") },
      { id: "assets", label: "Assets & connections", group: "Go to", icon: Boxes, keywords: "connect systems monitored", run: go("/assets") },
      { id: "activity", label: "Activity", group: "Go to", icon: ScrollText, keywords: "feed log agent", run: go("/activity") },
      { id: "settings", label: "Settings", group: "Go to", icon: Settings, keywords: "account organization notifications profile", run: go("/settings") },
    ];
    const actions: Cmd[] = [
      {
        id: "scan", label: "Scan now", group: "Actions", icon: RefreshCw, keywords: "rescan run trigger",
        run: () => { close(); startScan(() => { void rescanAll(); }); },
      },
      { id: "connect", label: "Connect a system", group: "Actions", icon: Plug, keywords: "oauth github okta google add", run: go("/assets") },
      {
        id: "signout", label: "Sign out", group: "Actions", icon: LogOut, keywords: "logout leave",
        run: () => { close(); fetch("/api/session", { method: "DELETE" }).then(() => { router.push("/login"); router.refresh(); }); },
      },
    ];
    const compliance: Cmd[] = FRAMEWORKS.map((fw) => ({
      id: `fw-${fw}`, label: `Compliance · ${FRAMEWORK_LABEL[fw] ?? fw}`, group: "Compliance",
      icon: ShieldCheck, keywords: `${fw} framework controls report`, run: go(`/compliance/${fw}`),
    }));
    return [...nav, ...actions, ...compliance];
  }, [router]); // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return commands;
    return commands.filter((c) => `${c.label} ${c.keywords ?? ""}`.toLowerCase().includes(needle));
  }, [commands, q]);

  // clamp selection when the filtered set shrinks
  useEffect(() => { setSel((s) => Math.min(s, Math.max(0, filtered.length - 1))); }, [filtered.length]);

  function onListKey(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, filtered.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); filtered[sel]?.run(); }
    else if (e.key === "Escape") { e.preventDefault(); close(); }
  }

  // keep the active row in view
  useEffect(() => {
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  if (!open) return null;

  let idx = -1;
  const groups: Cmd["group"][] = ["Go to", "Actions", "Compliance"];

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-bg/70 px-4 pt-[14vh] backdrop-blur-sm animate-fade-rise"
      onClick={close}
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <div
        className="w-full max-w-xl overflow-hidden rounded-xl border border-border-strong bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={onListKey}
      >
        <div className="flex items-center gap-2.5 border-b border-border px-4">
          <Search className="h-4 w-4 shrink-0 text-faint" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search or jump to…"
            className="w-full bg-transparent py-3.5 text-sm outline-none placeholder:text-faint"
            aria-label="Command"
          />
          <kbd className="mono rounded border border-border bg-bg px-1.5 py-0.5 text-[10px] text-faint">esc</kbd>
        </div>

        <div ref={listRef} className="max-h-[46vh] overflow-y-auto p-1.5">
          {filtered.length === 0 ? (
            <div className="px-3 py-8 text-center text-sm text-muted">No commands match “{q}”.</div>
          ) : (
            groups.map((g) => {
              const items = filtered.filter((c) => c.group === g);
              if (items.length === 0) return null;
              return (
                <div key={g} className="mb-1">
                  <div className="px-2.5 pb-1 pt-2 text-[10px] uppercase tracking-wider text-faint">{g}</div>
                  {items.map((c) => {
                    idx++;
                    const active = idx === sel;
                    const Icon = c.icon;
                    const here = idx;
                    return (
                      <button
                        key={c.id}
                        data-active={active}
                        onMouseEnter={() => setSel(here)}
                        onClick={c.run}
                        className={cn(
                          "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm transition",
                          active ? "bg-accent-soft text-ink" : "text-muted hover:bg-surface-2",
                        )}
                      >
                        <Icon className={cn("h-4 w-4 shrink-0", active ? "text-accent" : "text-faint")} />
                        <span className="flex-1">{c.label}</span>
                        {active && <CornerDownLeft className="h-3.5 w-3.5 text-faint" />}
                      </button>
                    );
                  })}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
