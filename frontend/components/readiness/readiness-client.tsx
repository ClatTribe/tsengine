"use client";

import { useState, useTransition } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  CheckCircle2, AlertTriangle, CircleDashed, UserCheck, MinusCircle, Wrench, ExternalLink,
} from "lucide-react";
import type { ReadinessChecklist, ReadinessItem } from "@/lib/types";
import { setStage, closeGap, attest } from "@/app/(app)/readiness/actions";
import { cn } from "@/lib/utils";

// The checklist, and the one question that scopes it.
//
// Five statuses, five treatments — deliberately NOT a red/green binary. "We looked and it is clean"
// and "we never looked" are different facts, and a checklist that paints them the same colour is
// worse than no checklist, because it converts an absence of evidence into a green tick.

const STATUS: Record<
  ReadinessItem["status"],
  { label: string; icon: typeof CheckCircle2; cls: string; dot: string }
> = {
  pass:        { label: "In place",     icon: CheckCircle2,  cls: "text-pulse",  dot: "bg-pulse" },
  gap:         { label: "Gap",          icon: AlertTriangle, cls: "text-high",   dot: "bg-high" },
  not_checked: { label: "Not checked",  icon: CircleDashed,  cls: "text-muted",  dot: "bg-muted" },
  needs_you:   { label: "Needs you",    icon: UserCheck,     cls: "text-accent", dot: "bg-accent" },
  not_covered: { label: "Not covered",  icon: MinusCircle,   cls: "text-faint",  dot: "bg-faint" },
};

// ── The onboarding question ──────────────────────────────────────────────────────────────────────

export function StagePicker({ stages }: { stages: { value: string; label: string; detail: string }[] }) {
  const [pending, start] = useTransition();
  const router = useRouter();
  const [error, setError] = useState("");

  return (
    <div className="card px-6 py-6">
      <h2 className="text-lg font-semibold text-ink">How far along is your company?</h2>
      <p className="mt-1.5 max-w-2xl text-sm text-muted">
        It decides what we measure you against. A seed team held to a Series C bar just sees a wall of
        red, so we only show what a company at your stage is expected to have. You can change it later.
      </p>
      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        {stages.map((s) => (
          <button
            key={s.value}
            disabled={pending}
            onClick={() =>
              start(async () => {
                const res = await setStage(s.value);
                if (!res.ok) setError(res.error || "Could not save that.");
                else router.refresh();
              })
            }
            className="card-hover rounded-md border border-border px-4 py-3 text-left transition disabled:opacity-50"
          >
            <div className="text-sm font-medium text-ink">{s.label}</div>
            <div className="mt-1 text-xs text-muted">{s.detail}</div>
          </button>
        ))}
      </div>
      {error && <p className="mt-3 text-xs text-critical">{error}</p>}
    </div>
  );
}

// ── The list ─────────────────────────────────────────────────────────────────────────────────────

export function ReadinessList({ data, me }: { data: ReadinessChecklist; me: string }) {
  const categories = Array.from(new Set(data.items.map((i) => i.category)));
  return (
    <div className="space-y-6">
      {categories.map((cat) => (
        <section key={cat}>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">{cat}</h3>
          <div className="space-y-2">
            {data.items.filter((i) => i.category === cat).map((item) => (
              <Row key={item.id} item={item} me={me} />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function Row({ item, me }: { item: ReadinessItem; me: string }) {
  const s = STATUS[item.status] ?? STATUS.not_checked;
  const Icon = s.icon;
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState("");
  const router = useRouter();

  return (
    <div className="card px-4 py-3">
      <div className="flex items-start gap-3">
        <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", s.cls)} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="text-sm font-medium text-ink">{item.text}</span>
            <span className={cn("text-[11px] font-medium", s.cls)}>{s.label}</span>
            {item.gap_count ? (
              <span className="text-[11px] text-muted">· {item.gap_count} open</span>
            ) : null}
          </div>
          <p className="mt-1 text-xs text-muted">{item.detail}</p>

          {/* The OSS that answers it. Naming the tool is what makes a tick checkable rather than
              trusted — a customer can run the same scanner and get the same answer. */}
          {item.tools?.length ? (
            <p className="mt-1.5 text-[11px] text-faint">
              Checked by {item.tools.join(", ")}
            </p>
          ) : null}

          <div className="mt-2.5 flex flex-wrap items-center gap-2">
            {item.status === "gap" && item.evidence === "observed" && (
              <button
                disabled={pending}
                onClick={() =>
                  start(async () => {
                    const res = await closeGap(item.id);
                    setMsg(res.ok ? res.detail || "" : res.error || "");
                    router.refresh();
                  })
                }
                className="btn-sm inline-flex items-center gap-1.5"
              >
                <Wrench className="h-3 w-3" />
                {pending ? "Working…" : "Close this gap"}
              </button>
            )}

            {item.status === "needs_you" && (
              <>
                <button
                  disabled={pending}
                  onClick={() =>
                    start(async () => {
                      const res = await attest(item.id, true, me);
                      if (!res.ok) setMsg(res.error || "");
                      router.refresh();
                    })
                  }
                  className="btn-sm"
                >
                  We do this
                </button>
                <button
                  disabled={pending}
                  onClick={() =>
                    start(async () => {
                      const res = await attest(item.id, false, me);
                      if (!res.ok) setMsg(res.error || "");
                      router.refresh();
                    })
                  }
                  className="btn-sm-ghost"
                >
                  Not yet
                </button>
              </>
            )}

            {item.status === "not_checked" && item.evidence === "observed" && (
              <Link href="/assets" className="btn-sm-ghost inline-flex items-center gap-1.5">
                Connect a system <ExternalLink className="h-3 w-3" />
              </Link>
            )}

            {item.agent && (
              <Link
                href={item.agent === "pentester" ? "/pentest" : "/engineer"}
                className="text-[11px] text-muted underline-offset-2 hover:underline"
              >
                {item.agent === "pentester" ? "AI Pentester" : "AI Security Engineer"} owns this
              </Link>
            )}
            {item.attested_by && (
              <span className="text-[11px] text-faint">Confirmed by {item.attested_by}</span>
            )}
          </div>

          {msg && <p className="mt-2 text-xs text-accent">{msg}</p>}
        </div>
      </div>
    </div>
  );
}
