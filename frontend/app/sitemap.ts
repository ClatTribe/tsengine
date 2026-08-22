import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { MetadataRoute } from "next";
import { FRAMEWORKS } from "@/lib/frameworks";
import { POSTS } from "@/lib/blog";
import { RESOURCE_LIST } from "@/lib/resources";
import { SITE_URL } from "@/lib/site";

// The public, crawlable surface. Authed app routes (under (app)) are intentionally excluded;
// they redirect to /login.
//
// EVERYTHING HERE IS DERIVED. NOTHING IS HAND-LISTED.
//
// This file used to state that rule in a comment and apply it to only half of itself: blog
// posts and resources were generated from POSTS and RESOURCE_LIST, while the static marketing
// routes sat in a hand-maintained `staticPaths` array immediately above them. Three routes had
// already drifted out of it — /solutions (which also had zero inbound links, so nothing could
// reach it at all), /docs and /agent-controls. The diagnosis in the old comment was right and
// the fix covered half the file. ADR 0023 decision 4.
//
// Walking the route tree is safe here because a sitemap is a STATIC metadata route: it runs
// once during `next build`, in the builder stage where app/ exists, and the rendered XML is
// what ships. If that ever changes to a dynamic route, this must change with it.
const MARKETING_DIR = join(process.cwd(), "app", "(marketing)");

/**
 * marketingRoutes walks app/(marketing) and returns every concrete route path.
 *
 * Dynamic segments are skipped — [framework], [slug] and friends are enumerated below from the
 * same arrays their pages render from, which is the only way the two can't disagree.
 */
function marketingRoutes(dir = MARKETING_DIR, prefix = ""): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (entry === "page.tsx") {
      out.push(prefix);
      continue;
    }
    if (!statSync(full).isDirectory()) continue;
    if (entry.startsWith("[")) continue; // dynamic — enumerated explicitly below
    if (entry.startsWith("_") || entry.startsWith(".")) continue;
    // A route group like (marketing) contributes no URL segment.
    const segment = entry.startsWith("(") && entry.endsWith(")") ? prefix : `${prefix}/${entry}`;
    out.push(...marketingRoutes(full, segment));
  }
  return out;
}

export default function sitemap(): MetadataRoute.Sitemap {
  const paths = marketingRoutes();

  // Fail loudly rather than shipping an empty sitemap. A silent zero here would de-list the
  // entire site at exactly the moment nobody is looking — the same reason the metadata guard
  // fails instead of skipping when it cannot find a build (ADR 0022's dead guard).
  if (paths.length === 0) {
    throw new Error(
      `sitemap: found no marketing routes under ${MARKETING_DIR}. ` +
        `If the route layout moved, update MARKETING_DIR — do not ship an empty sitemap.`,
    );
  }

  const pages = paths.map((p) => ({
    url: `${SITE_URL}${p}`,
    // changefreq and priority are deliberately absent: Google states it ignores both. The
    // signal it does use is lastModified, and we only have a real one for dated content —
    // inventing a date for a static page would be a fabricated freshness signal.
    ...(p === "" ? { priority: 1 } : {}),
  }));

  const frameworkPages = FRAMEWORKS.map((f) => ({ url: `${SITE_URL}/frameworks/${f}` }));

  // lastModified comes from the post's own date, so a crawler can tell a revised post from an
  // untouched one.
  const blogPages = POSTS.map((p) => ({
    url: `${SITE_URL}/blog/${p.slug}`,
    lastModified: new Date(p.date),
  }));

  const resourcePages = RESOURCE_LIST.map((r) => ({ url: `${SITE_URL}/resources/${r.slug}` }));

  return [...pages, ...frameworkPages, ...blogPages, ...resourcePages];
}
