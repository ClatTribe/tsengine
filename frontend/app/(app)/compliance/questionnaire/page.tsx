import Link from "next/link";
import { ArrowLeft, Download, CheckCircle2, CircleDashed, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import type { QAnswer } from "@/lib/types";
import { Empty } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function QuestionnairePage() {
  const q = await api.questionnaire();
  const answers = q?.answers ?? []; // Go marshals an empty slice as null — guard before .length/.map

  if (!q || answers.length === 0) {
    return (
      <div className="mx-auto max-w-3xl space-y-5">
        <Back />
        <Empty>No questionnaire yet — connect a system so the agent can assess your controls.</Empty>
      </div>
    );
  }

  // group by domain, preserving first-seen order
  const groups: { domain: string; items: QAnswer[] }[] = [];
  for (const a of answers) {
    const last = groups[groups.length - 1];
    if (last && last.domain === a.domain) last.items.push(a);
    else groups.push({ domain: a.domain, items: [a] });
  }
  const total = answers.length;
  const pct = Math.round((q.yes / total) * 100);

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <Back />

      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-accent/40 bg-accent-soft text-accent">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">Security questionnaire</h1>
            <p className="text-xs text-muted">Auto-answered from live control state — the answers a buyer&apos;s procurement team asks for.</p>
          </div>
        </div>
        <a
          href="/api/questionnaire"
          className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted transition hover:border-border-strong hover:text-ink"
        >
          <Download className="h-3.5 w-3.5" /> Download
        </a>
      </div>

      {/* Coverage summary */}
      <div className="card p-5">
        <div className="flex items-end justify-between">
          <div>
            <div className="text-2xl font-semibold text-pulse">{pct}%</div>
            <div className="text-xs text-muted">answered &ldquo;Yes&rdquo; from evidence</div>
          </div>
          <div className="text-right text-xs">
            <span className="text-pulse">{q.yes} Yes</span>
            <span className="text-faint"> · </span>
            <span className="text-medium">{q.in_progress} In Progress</span>
          </div>
        </div>
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface-2">
          <div className="h-full rounded-full bg-pulse transition-all" style={{ width: `${pct}%` }} />
        </div>
      </div>

      {groups.map((g) => (
        <section key={g.domain}>
          <h2 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted">{g.domain}</h2>
          <div className="card divide-y divide-border p-0">
            {g.items.map((a) => (
              <Row key={a.id} answer={a} />
            ))}
          </div>
        </section>
      ))}

      <p className="text-[11px] leading-relaxed text-faint">
        Grounded: an &ldquo;In Progress&rdquo; answer reflects a real finding that created a control gap; &ldquo;Yes&rdquo; means no finding
        contradicts the control. Nothing here is asserted without evidence.
      </p>
    </div>
  );
}

function Row({ answer: a }: { answer: QAnswer }) {
  const yes = a.answer === "Yes";
  const Icon = yes ? CheckCircle2 : CircleDashed;
  return (
    <div className="flex items-start gap-3 px-5 py-3.5">
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", yes ? "text-pulse" : "text-medium")} />
      <div className="min-w-0 flex-1">
        <div className="text-sm">{a.text}</div>
        {!yes && (a.gap_controls?.length || a.evidence_ids?.length) ? (
          <div className="mono mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-faint">
            {a.gap_controls?.map((c) => (
              <span key={c} className="rounded border border-border bg-bg px-1.5 py-0.5">{c}</span>
            ))}
            {a.evidence_ids?.map((id) => (
              <Link key={id} href={`/findings/${id}`} className="text-accent hover:underline">
                {id}
              </Link>
            ))}
          </div>
        ) : null}
      </div>
      <span
        className={cn(
          "shrink-0 rounded-md border px-1.5 py-0.5 text-[11px] font-medium",
          yes ? "border-pulse/30 bg-pulse/10 text-pulse" : "border-medium/30 bg-medium/10 text-medium",
        )}
      >
        {a.answer}
      </span>
    </div>
  );
}

function Back() {
  return (
    <Link href="/compliance" className="inline-flex items-center gap-1.5 text-xs text-muted transition hover:text-ink">
      <ArrowLeft className="h-3.5 w-3.5" /> Compliance
    </Link>
  );
}
