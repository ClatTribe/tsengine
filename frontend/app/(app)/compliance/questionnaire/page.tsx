import Link from "next/link";
import { ArrowLeft, Download, CheckCircle2, CircleDashed, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { AttestAnswer } from "@/components/compliance/attest-answer";
import type { QAnswer } from "@/lib/types";
import { Empty } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function QuestionnairePage() {
  const [q, me] = await Promise.all([api.questionnaire(), api.me()]);
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
  // The percentage is over the OBSERVED half ONLY, and says so.
  //
  // yes/total would mix the two tiers, and it would be wrong in both directions: adding
  // attested questions makes the figure fall although nothing got worse, and once someone
  // answers them it RISES on the strength of typed assertions while the label still claims
  // "from evidence". One number over two kinds of evidence is a number nobody can act on.
  const observed = q.observed ?? total;
  const pct = observed > 0 ? Math.round(((q.observed_yes ?? 0) / observed) * 100) : 0;
  // Both admissions are shown as prominently as the score, and SEPARATELY — a questionnaire that
  // is mostly unanswered must LOOK mostly unanswered, and the two kinds of unanswered need
  // different action: one is fixed by connecting a system, the other by a person answering.
  const notAssessed = q.not_assessed ?? 0;
  const needsYou = q.needs_you ?? 0;

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
            {/* The denominator is named. A bare percentage over a mixed corpus would rise when
                someone types an answer and fall when questions are added, meaning neither. */}
            <div className="text-xs text-muted">
              of the {observed} questions we can evidence
            </div>
          </div>
          <div className="text-right text-xs">
            <span className="text-pulse">{q.observed_yes ?? 0} Yes</span>
            <span className="text-faint"> · </span>
            <span className="text-medium">{q.in_progress} In Progress</span>
            {notAssessed > 0 && (
              <>
                <span className="text-faint"> · </span>
                <span className="text-faint">{notAssessed} Not assessed</span>
              </>
            )}
          </div>
        </div>
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface-2">
          <div className="h-full rounded-full bg-pulse transition-all" style={{ width: `${pct}%` }} />
        </div>
        {notAssessed > 0 && (
          <p className="mt-3 text-xs leading-relaxed text-muted">
            <span className="font-medium text-ink">{notAssessed} question{notAssessed === 1 ? "" : "s"} have no evidence source connected.</span>{" "}
            They are reported as <span className="text-faint">Not assessed</span> rather than assumed compliant —
            each row names what to connect.
          </p>
        )}
        {/* The SECOND admission, stated separately. Merged with the one above, the reader would
            be told to connect a system for a question no system can answer. */}
        {needsYou > 0 && (
          <p className="mt-2 text-xs leading-relaxed text-muted">
            <span className="font-medium text-ink">{needsYou} of the {q.attested ?? 0} questions no scan can reach still need your answer.</span>{" "}
            Background checks, physical security, whether the recovery plan was actually tested — nobody can
            observe these, so they stay unanswered until you say. Answer them inline below.
          </p>
        )}
      </div>

      {groups.map((g) => (
        <section key={g.domain}>
          <h2 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted">{g.domain}</h2>
          <div className="card divide-y divide-border p-0">
            {g.items.map((a) => (
              <Row key={a.id} answer={a} who={me?.email ?? ""} />
            ))}
          </div>
        </section>
      ))}

      <p className="text-[11px] leading-relaxed text-faint">
        Grounded: an &ldquo;In Progress&rdquo; answer reflects a real finding that created a control gap; &ldquo;Yes&rdquo; on an
        evidenced question means the source is connected and no finding contradicts the control. Rows marked{" "}
        <span className="text-muted">stated by</span> are answered by a named person because no scan can establish
        them — a buyer sees them as an assertion, not as something we observed.
      </p>
    </div>
  );
}

function Row({ answer: a, who }: { answer: QAnswer; who: string }) {
  const yes = a.answer === "Yes";
  const attested = a.evidence === "attested";
  const Icon = yes ? CheckCircle2 : CircleDashed;
  return (
    <div className="flex items-start gap-3 px-5 py-3.5">
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", yes ? "text-pulse" : "text-medium")} />
      <div className="min-w-0 flex-1">
        <div className="text-sm">{a.text}</div>

        {/* An attested row must never read like an evidenced one. Answered, it names the person;
            unanswered, it says why nothing can answer it and offers the control. */}
        {attested && a.attested_by && (
          <div className="mt-1 text-[11px] text-muted">
            stated by <span className="text-ink">{a.attested_by}</span>
            {a.attested_at ? ` on ${new Date(a.attested_at).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })}` : ""}
            {a.attested_note ? ` — ${a.attested_note}` : ""}
          </div>
        )}
        {attested && !a.attested_by && (
          <>
            {a.why && <div className="mt-1 text-[11px] text-faint">{a.why}</div>}
            <AttestAnswer id={a.id} who={who} />
          </>
        )}

        {!attested && a.answer === "Not assessed" && a.missing_sources?.length ? (
          <div className="mt-1 text-[11px] text-faint">
            connect {a.missing_sources.join(" or ")} to answer this
          </div>
        ) : null}

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
