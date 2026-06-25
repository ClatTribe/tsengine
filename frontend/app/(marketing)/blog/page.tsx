import Link from "next/link";
import { ArrowRight, BookOpen } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { POSTS, STAGE_META, type FunnelStage } from "@/lib/blog";

export const metadata = pageMeta({
  title: "Blog — Security & SOC 2 for startups | TensorShield",
  description:
    "Plain-English security and SOC 2 guidance for founders: passing enterprise security questionnaires, getting audit-ready, and fixing the gaps that block deals — with free tools at every step.",
  path: "/blog",
});

const STAGE_ORDER: FunnelStage[] = ["ToFu", "MoFu", "BoFu"];

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}

export default function BlogIndex() {
  return (
    <section className="mx-auto max-w-4xl px-5 pb-24 pt-20">
      <div className="text-center">
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-accent">
          <BookOpen className="h-3.5 w-3.5" /> Blog
        </span>
        <h1 className="mx-auto mt-3 max-w-2xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
          Security &amp; SOC 2, in founder language
        </h1>
        <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
          No jargon, no fear-selling — just what an enterprise buyer&apos;s security review actually checks, and how to
          be ready. Each guide comes with a free tool.
        </p>
      </div>

      <div className="mt-14 space-y-12">
        {STAGE_ORDER.map((stage) => {
          const posts = POSTS.filter((p) => p.stage === stage);
          if (posts.length === 0) return null;
          return (
            <div key={stage}>
              <div className="mb-4 flex items-baseline gap-2">
                <h2 className="text-sm font-semibold uppercase tracking-wider text-ink">{STAGE_META[stage].label}</h2>
                <span className="text-xs text-faint">{STAGE_META[stage].blurb}</span>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                {posts.map((p) => (
                  <Link
                    key={p.slug}
                    href={`/blog/${p.slug}`}
                    className="group card flex flex-col p-5 transition hover:border-border-strong"
                  >
                    <div className="text-[11px] font-medium uppercase tracking-wide text-accent">{STAGE_META[stage].label}</div>
                    <h3 className="mt-1.5 text-lg font-semibold leading-snug tracking-tight group-hover:text-accent">{p.title}</h3>
                    <p className="mt-2 flex-1 text-sm leading-relaxed text-muted">{p.description}</p>
                    <div className="mt-4 flex items-center justify-between text-xs text-faint">
                      <span>{fmtDate(p.date)} · {p.readMins} min read</span>
                      <ArrowRight className="h-4 w-4 transition group-hover:translate-x-0.5 group-hover:text-accent" />
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
