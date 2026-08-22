import Link from "next/link";
import { ArrowRight, BookOpen, AlertTriangle } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { DOC_SECTIONS } from "@/lib/docs";

export const metadata = pageMeta({
  title: "Docs — how to use TensorShield",
  description:
    "How to use TensorShield: connect your stack, read the findings, approve the fixes, and produce the compliance evidence. Including what each agent needs, and what we deliberately do not do.",
  path: "/docs",
});

export default function Docs() {
  return (
    <>
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl animate-fade-rise px-5 pb-10 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <BookOpen className="h-3.5 w-3.5 text-accent" /> Documentation
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            How to use TensorShield
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            Connect your stack, read what it finds, approve the fixes, and hand your auditor the evidence. Every step
            below says what it needs before it will do anything — including the ones that need a model or a scan.
          </p>
        </div>
      </section>

      {/* Section index — a doc you cannot navigate is a doc nobody finishes. */}
      <section className="mx-auto max-w-3xl px-5">
        <nav className="flex flex-wrap justify-center gap-2">
          {DOC_SECTIONS.map((s) => (
            <a
              key={s.id}
              href={`#${s.id}`}
              className="rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-ink"
            >
              {s.title}
            </a>
          ))}
        </nav>
      </section>

      <section className="mx-auto max-w-3xl space-y-14 px-5 py-14">
        {DOC_SECTIONS.map((s) => (
          <div key={s.id} id={s.id} className="scroll-mt-24">
            <h2 className="text-2xl font-semibold tracking-tight">{s.title}</h2>
            <p className="mt-2 leading-relaxed text-muted">{s.intro}</p>

            {s.steps && (
              <ol className="mt-6 space-y-4">
                {s.steps.map((st) => (
                  <li key={st.title} className="card flex gap-4 p-4">
                    <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-accent-soft text-xs font-semibold text-accent">
                      {st.n}
                    </span>
                    <div>
                      <div className="text-sm font-semibold">{st.title}</div>
                      <p className="mt-1 text-sm leading-relaxed text-muted">{st.body}</p>
                      {/* The prerequisite rides ON the step, not in a footnote. A reader who follows
                          the step and hits a refusal should have been told here. */}
                      {st.needs && (
                        <p className="mt-2 flex items-start gap-1.5 text-xs leading-relaxed text-faint">
                          <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-accent" />
                          <span>
                            <span className="font-medium text-muted">Needs:</span> {st.needs}
                          </span>
                        </p>
                      )}
                    </div>
                  </li>
                ))}
              </ol>
            )}

            {s.rows && (
              <dl className="mt-6 divide-y divide-border overflow-hidden rounded-xl border border-border">
                {s.rows.map((r) => (
                  <div key={r.k} className="grid gap-1 p-4 sm:grid-cols-3 sm:gap-4">
                    <dt className="mono text-xs font-medium text-ink sm:text-[13px]">{r.k}</dt>
                    <dd className="text-sm leading-relaxed text-muted sm:col-span-2">{r.v}</dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        ))}
      </section>

      <section className="mx-auto max-w-3xl px-5 pb-24">
        <div className="card flex flex-col items-center gap-4 p-8 text-center">
          <h2 className="text-xl font-semibold tracking-tight">Start with one system</h2>
          <p className="max-w-lg text-sm leading-relaxed text-muted">
            Connect a repo or a cloud account and you will have real findings, mapped to controls, within a scan. The
            free tier runs the scanning engine; add your own model key when you want the agents.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/signup"
              className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover"
            >
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/sample-report"
              className="inline-flex items-center gap-2 rounded-xl border border-border px-5 py-3 text-sm font-semibold transition hover:border-accent/40"
            >
              See a finished report
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
