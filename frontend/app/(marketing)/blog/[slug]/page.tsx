import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, ArrowRight } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { ArticleJsonLd } from "@/components/marketing/article-jsonld";
import { POSTS, postBySlug, readMinutes, relatedPosts, type Block } from "@/lib/blog";

export function generateStaticParams() {
  return POSTS.map((p) => ({ slug: p.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const post = postBySlug((await params).slug);
  if (!post) return pageMeta({ title: "Not found", description: "", path: "/blog" });
  // seoTitle when the headline is too long for a search result; the h1 keeps the full headline.
  // socialTitle stays the editorial one — a share card has room the SERP does not.
  return pageMeta({
    title: post.seoTitle ?? post.title,
    description: post.description,
    path: `/blog/${post.slug}`,
    socialTitle: post.title,
  });
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}

function BlockView({ b }: { b: Block }) {
  switch (b.t) {
    case "h2":
      return <h2 className="mt-10 text-2xl font-semibold tracking-tight">{b.text}</h2>;
    case "p":
      return <p className="mt-4 text-[15px] leading-relaxed text-muted">{b.text}</p>;
    case "ul":
      return (
        <ul className="mt-4 space-y-2">
          {b.items.map((it, i) => (
            <li key={i} className="flex gap-2.5 text-[15px] leading-relaxed text-muted">
              <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-accent/60" />
              <span>{it}</span>
            </li>
          ))}
        </ul>
      );
    case "cta":
      return (
        <div className="my-7 rounded-2xl border border-accent/30 bg-accent-soft/30 p-5 text-center">
          <p className="text-sm font-medium text-ink">{b.text}</p>
          <Link
            href={b.href}
            className="mt-3 inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
          >
            {b.label} <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      );
  }
}

export default async function BlogPostPage({ params }: { params: Promise<{ slug: string }> }) {
  const post = postBySlug((await params).slug);
  if (!post) notFound();

  return (
    <article className="mx-auto max-w-2xl px-5 pb-24 pt-16">
      <ArticleJsonLd post={post} />
      <Link href="/blog" className="inline-flex items-center gap-1.5 text-sm text-muted transition hover:text-accent">
        <ArrowLeft className="h-4 w-4" /> All posts
      </Link>

      <div className="mt-6">
        <div className="text-[11px] font-medium uppercase tracking-wide text-accent">{post.category}</div>
        <h1 className="mt-2 text-3xl font-semibold leading-[1.15] tracking-tight sm:text-4xl">{post.title}</h1>
        <p className="mt-3 text-base leading-relaxed text-muted">{post.description}</p>
        <div className="mt-4 text-xs text-faint">{fmtDate(post.date)} · {readMinutes(post)} min read</div>
      </div>

      <div className="mt-8 border-t border-border pt-2">
        {post.body.map((b, i) => (
          <BlockView key={i} b={b} />
        ))}
      </div>

      {/* Related reading — ADR 0023 decision 5. Until this existed no post could link to another
          post at all (the Block type has no link and paragraph text renders escaped), so eight
          articles on one theme read to a crawler as eight unrelated pages. relatedPosts() always
          returns neighbours, curated or not, so every post carries links out. */}
      <nav aria-labelledby="related-heading" className="mt-12 border-t border-border pt-6">
        <h2 id="related-heading" className="text-xs font-semibold uppercase tracking-wider text-faint">
          Related reading
        </h2>
        <ul className="mt-3 grid gap-2 sm:grid-cols-3">
          {relatedPosts(post).map((r) => (
            <li key={r.slug}>
              <Link
                href={`/blog/${r.slug}`}
                className="group flex items-start gap-2 text-sm leading-relaxed text-muted transition hover:text-ink"
              >
                <ArrowRight className="mt-1 h-3.5 w-3.5 shrink-0 text-faint transition group-hover:translate-x-0.5 group-hover:text-accent" />
                <span>{r.title}</span>
              </Link>
            </li>
          ))}
        </ul>
      </nav>

      <div className="mt-12 rounded-2xl border border-border bg-surface-2 p-6 text-center">
        <p className="text-sm font-medium text-ink">See where your security stands — free, no signup.</p>
        <Link href="/scan" className="mt-3 inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-accent-hover">
          Run the free scan <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
    </article>
  );
}
