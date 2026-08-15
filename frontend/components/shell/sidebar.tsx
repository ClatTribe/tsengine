"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Inbox,
  ShieldCheck,
  Boxes,
  Layers,
  Crosshair,
  ChevronDown,
  Sparkles,
  ClipboardCheck,
} from "lucide-react";
import { LogoMark } from "@/components/brand/logo";
import { cn } from "@/lib/utils";

type NavItem = { href: string; label: string; icon: typeof LayoutDashboard; badgeKey?: "pending" };

// Grouped IA — the nav mirrors the product's architecture so a founder reads the thesis from the
// sidebar: the product sells TWO THINGS — an AI Security Engineer (defence) and an AI Pentester
// (attack) — so the navigation is shaped like that, not like a catalogue of surfaces.
//
// It used to be outcome-led (Security / GRC / Connections) with the engineer deliberately "sprinkled"
// as verbs on objects and no destination of its own. That produced a real asymmetry: the Pentester had
// a row and a page, the Engineer had a console at /brief that NOTHING in the navigation reached — its
// own depth specialists linked "back to the AI Security Engineer" at a place you could not get to. One
// of the two products was invisible.
//
// Now each agent is a top-level product with everything its job needs, and the surfaces they produce
// sit underneath the agent that produces them: Issues is what the Engineer found; the pentest report is
// what the Pentester proved. Inbox stays pinned at the top because it is the HUMAN's half of the loop —
// the agent proposes, you approve — and it belongs to both agents, not to either one.
//
// Adding a route → put it under the agent whose work it is, or under the outcome it serves. Do not grow
// a flat list.
const NAV_GROUPS: { header?: string; items: NavItem[] }[] = [
  {
    items: [
      { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
      // The human's half of the loop: every change either agent proposes waits here with its diff.
      { href: "/inbox", label: "Inbox", icon: Inbox, badgeKey: "pending" },
    ],
  },
  {
    // PRODUCT 1 — the defender. The console is the front door (ask your estate, triage, propose fixes,
    // delegate to the code/cloud specialists); Issues is what it found, kept one click away because it
    // is the daily driver for a developer who does not want to go through the agent every time.
    header: "AI Security Engineer",
    items: [
      { href: "/engineer", label: "Console", icon: Sparkles },
      { href: "/issues", label: "Issues", icon: Layers },
    ],
  },
  {
    // PRODUCT 2 — the attacker. A scope → authorize → run → report engagement.
    header: "AI Pentester",
    items: [
      { href: "/pentest", label: "Engagements", icon: Crosshair },
    ],
  },
  {
    // ONE ROW PER DESTINATION, artifacts as tabs on it (lib/tabs.ts). Compliance was four rows —
    // Posture, Risks, Audits, Program — and Connections three. Seven rows for two ideas: "am I
    // audit-ready" and "what have I connected". A reader had to know what "Program" meant before
    // deciding whether they wanted it, and the sidebar grew with every page added. Same pages, same
    // click count, far less to hold in your head.
    items: [
      { href: "/readiness", label: "Readiness", icon: ClipboardCheck },
      { href: "/compliance", label: "Compliance", icon: ShieldCheck },
      { href: "/assets", label: "Connections", icon: Boxes },
    ],
  },
];

const COLLAPSE_KEY = "ts.nav.collapsed";

// selfOwned (service-model): when the logged-in tenant OWNS the HITL acts (self_serve) the pending badge
// is an accent to-do; for managed/msp the expert owns them, so the badge is informational (muted) — not
// a nag. Defaults true so nothing changes when the flag isn't passed.
export function Sidebar({
  pending,
  selfOwned = true,
  halted = false,
  aiEnabled = true,
}: {
  pending: number;
  selfOwned?: boolean;
  /** Kill-switch engaged — no scans or fixes are running (§18.2 inv. 7). */
  halted?: boolean;
  /** An LLM is configured, so the AI engineer/pentester can actually reason. */
  aiEnabled?: boolean;
}) {
  const path = usePathname();
  // which group headers are collapsed — persisted so a founder's tidied-up nav sticks across sessions.
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [ready, setReady] = useState(false);
  useEffect(() => {
    try {
      const raw = localStorage.getItem(COLLAPSE_KEY);
      if (raw) setCollapsed(JSON.parse(raw));
    } catch {
      /* ignore malformed/absent state */
    }
    setReady(true);
  }, []);
  const toggle = (header: string) =>
    setCollapsed((prev) => {
      const next = { ...prev, [header]: !prev[header] };
      try {
        localStorage.setItem(COLLAPSE_KEY, JSON.stringify(next));
      } catch {
        /* storage may be unavailable */
      }
      return next;
    });

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-bg/60 px-3 py-4">
      <Link href="/dashboard" className="mb-6 flex items-center gap-2.5 px-2">
        <div className="grid h-8 w-8 place-items-center rounded-lg bg-[#0b1220] ring-1 ring-white/10">
          <LogoMark className="h-5 w-5" />
        </div>
        <span className="text-sm font-semibold">TensorShield</span>
      </Link>

      <nav className="flex flex-1 flex-col gap-3 overflow-y-auto">
        {NAV_GROUPS.map((group, gi) => {
          // an active route inside a collapsed group forces it open (never hide where you are)
          const hasActive = group.items.some((it) => path === it.href || path.startsWith(it.href + "/"));
          const isCollapsed = ready && !!group.header && !!collapsed[group.header] && !hasActive;
          return (
            <div key={group.header ?? `g${gi}`} className="flex flex-col gap-0.5">
              {group.header && (
                <button
                  type="button"
                  onClick={() => toggle(group.header!)}
                  className="group/header flex items-center gap-1 px-2.5 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-faint transition hover:text-muted"
                  aria-expanded={!isCollapsed}
                >
                  <ChevronDown className={cn("h-3 w-3 transition-transform", isCollapsed && "-rotate-90")} />
                  <span className="flex-1 text-left">{group.header}</span>
                </button>
              )}
              {!isCollapsed &&
                group.items.map(({ href, label, icon: Icon, badgeKey }) => {
                  const active = path === href || path.startsWith(href + "/");
                  const badge = badgeKey === "pending" && pending > 0 ? pending : null;
                  return (
                    <Link
                      key={href}
                      href={href}
                      className={cn(
                        "group flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition",
                        active ? "bg-surface-2 text-ink" : "text-muted hover:bg-surface hover:text-ink",
                      )}
                    >
                      <Icon className={cn("h-4 w-4 transition", active ? "text-accent" : "text-faint group-hover:text-muted")} />
                      <span className="flex-1">{label}</span>
                      {badge != null && (
                        <span
                          className={cn(
                            "rounded-full px-1.5 py-px text-[10px] font-semibold",
                            selfOwned ? "bg-accent text-bg" : "bg-surface-2 text-muted",
                          )}
                        >
                          {badge}
                        </span>
                      )}
                    </Link>
                  );
                })}
            </div>
          );
        })}
      </nav>

      <AgentStatus halted={halted} aiEnabled={aiEnabled} />
    </aside>
  );
}

// AgentStatus reports what is ACTUALLY running.
//
// This used to be the literal string "agent online" beside a pulsing dot, wired to nothing. Engaging
// the kill-switch — the one control whose entire purpose is to stop every agent — left it reading
// "agent online" directly beneath a banner saying automation was halted. The page contradicted itself
// about a safety control, and the reassuring half was the one that was always on.
//
// The layout already resolves both facts to render its banners, so this needs no new fetch; it only
// needed to be told.
function AgentStatus({ halted, aiEnabled }: { halted: boolean; aiEnabled: boolean }) {
  // Halted wins: it is the state a human deliberately chose, and the one they most need reflected.
  if (halted) {
    return (
      <div className="mt-4 px-2 pt-2 text-[11px] text-high">
        <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-high align-middle" />
        automation halted
      </div>
    );
  }
  // Without a model the deterministic scanners still run — this is a real, useful state, not an
  // outage. Saying "agent online" here would promise reasoning that cannot happen.
  if (!aiEnabled) {
    return (
      <div className="mt-4 px-2 pt-2 text-[11px] text-faint">
        <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-faint align-middle" />
        deterministic scans only
      </div>
    );
  }
  return (
    <div className="mt-4 px-2 pt-2 text-[11px] text-faint">
      <span className="pulse-dot mr-1.5 align-middle" /> agent online
    </div>
  );
}
