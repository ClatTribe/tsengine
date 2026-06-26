import Link from "next/link";
import { ArrowRight, FileText, BookOpen } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { RESOURCE_LIST } from "@/lib/resources";

export const metadata = pageMeta({
  title: "Free Security & Compliance Resources for Founders | TensorShield",
  description:
    "Free, no-fluff resources for founders tackling security and compliance: a SOC 2 readiness checklist and a security-questionnaire response template. The consultant's deliverables, free.",
  path: "/resources",
});

export default function Resources() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl animate-fade-rise px-5 pb-10 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <BookOpen className="h-3.5 w-3.5 text-accent" /> Free resources
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            The consultant&apos;s deliverables — free.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            The checklists and templates a security &amp; compliance consultant charges thousands for, written for
            founders. Grab them, use them, and when you want them <em>done</em> instead of documented, we&apos;re here.
          </p>
        </div>
      </section>

      {/* Resource cards */}
      <section className="mx-auto max-w-4xl px-5 pb-24">
        <div className="grid gap-5 sm:grid-cols-2">
          {RESOURCE_LIST.map((r) => (
            <Link key={r.slug} href={`/resources/${r.slug}`} className="card group flex flex-col p-6 transition hover:border-accent/50">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
                <FileText className="h-4 w-4" /> Free {r.kind}
              </div>
              <h2 className="mt-3 text-lg font-semibold leading-snug tracking-tight text-ink">{r.title}</h2>
              <p className="mt-2 flex-1 text-sm leading-relaxed text-muted">{r.subtitle}</p>
              <div className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-accent">
                Get it free <ArrowRight className="h-4 w-4 transition group-hover:translate-x-0.5" />
              </div>
            </Link>
          ))}
        </div>
        <p className="mt-8 text-center text-sm text-muted">
          Want a free, instant read on where you stand?{" "}
          <Link href="/scan" className="font-medium text-accent hover:underline">Run the questionnaire scan</Link> — no email required.
        </p>
      </section>
    </>
  );
}
