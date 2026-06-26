import { notFound } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, CheckSquare } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { ResourceGate } from "@/components/marketing/resource-gate";
import { RESOURCES, RESOURCE_LIST } from "@/lib/resources";

export function generateStaticParams() {
  return RESOURCE_LIST.map((r) => ({ slug: r.slug }));
}

export function generateMetadata({ params }: { params: { slug: string } }) {
  const r = RESOURCES[params.slug];
  if (!r) return {};
  return pageMeta({ title: r.seoTitle, description: r.seoDesc, path: `/resources/${r.slug}` });
}

export default function ResourcePage({ params }: { params: { slug: string } }) {
  const r = RESOURCES[params.slug];
  if (!r) notFound();

  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl animate-fade-rise px-5 pb-10 pt-16 text-center">
          <Link href="/resources" className="inline-flex items-center gap-1.5 text-xs font-medium text-muted transition hover:text-ink">
            <ArrowLeft className="h-3.5 w-3.5" /> All free resources
          </Link>
          <span className="mt-5 inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-accent shadow-sm">
            Free {r.kind}
          </span>
          <h1 className="mt-4 text-3xl font-semibold leading-[1.1] tracking-tight sm:text-4xl">{r.title}</h1>
          <p className="mx-auto mt-4 max-w-xl text-base leading-relaxed text-muted">{r.subtitle}</p>
        </div>
      </section>

      {/* Hook + gate */}
      <section className="mx-auto max-w-4xl px-5 pb-8">
        <p className="mx-auto mb-8 max-w-2xl text-center text-sm leading-relaxed text-muted">{r.blurb}</p>
        <ResourceGate slug={r.slug} title={r.title} takeaways={r.takeaways}>
          {/* Gated content — SSR'd, revealed on unlock, printable */}
          <article className="space-y-8">
            {r.sections.map((s) => (
              <div key={s.heading}>
                <h2 className="text-lg font-semibold tracking-tight text-ink">{s.heading}</h2>
                {s.intro && <p className="mt-1.5 text-sm leading-relaxed text-muted">{s.intro}</p>}
                <ul className="mt-3 space-y-2.5">
                  {s.items.map((it) => (
                    <li key={it} className="flex items-start gap-2.5 text-sm leading-relaxed text-ink">
                      <CheckSquare className="mt-0.5 h-4 w-4 shrink-0 text-accent" /> <span>{it}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </article>
        </ResourceGate>
      </section>
    </>
  );
}
