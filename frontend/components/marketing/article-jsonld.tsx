import { SITE_URL } from "@/lib/site";
import type { Post } from "@/lib/blog";

// ArticleJsonLd emits schema.org BlogPosting structured data for a blog post — what lets a post
// show as an article rich result rather than a plain blue link.
//
// Driven by the SAME Post object the page renders, so the markup can never drift from the visible
// content (the rule FaqJsonLd follows, and the one Google enforces). Everything here is derived:
// the headline is the post's title, the body text is the post's own paragraph blocks, and the
// publisher is the Organization node the marketing layout already declares — so this adds no claim
// the page doesn't make (CLAUDE.md §10).
//
// Deliberately NOT emitted: `dateModified` (we track one date per post, and inventing a modified
// date would tell a crawler a post was revised when it wasn't) and `author` as a named Person
// (posts are house-written; a fabricated byline is exactly the sort of unearned authority signal
// the rest of this site refuses to fake). Publisher-as-author is honest and valid.
export function ArticleJsonLd({ post }: { post: Post }) {
  const url = `${SITE_URL}/blog/${post.slug}`;
  // Prose only — headings and list items are structure, CTAs are UI, neither is article body text.
  const bodyText = post.body
    .filter((b): b is { t: "p"; text: string } => b.t === "p")
    .map((b) => b.text)
    .join(" ");

  const data = {
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    "@id": `${url}#article`,
    mainEntityOfPage: { "@type": "WebPage", "@id": url },
    url,
    headline: post.title,
    description: post.description,
    articleSection: post.category,
    datePublished: post.date,
    inLanguage: "en",
    wordCount: bodyText.split(/\s+/).filter(Boolean).length,
    publisher: { "@id": `${SITE_URL}/#organization` },
    author: { "@id": `${SITE_URL}/#organization` },
    isPartOf: { "@id": `${SITE_URL}/#website` },
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}
