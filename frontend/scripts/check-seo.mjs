// Guards the marketing surface against the defects that are INVISIBLE IN SOURCE.
//
//   npm run check:seo        (after `npm run build`)
//
// Why this reads the built HTML rather than the pages (ADR 0023 decision 7). Every finding it
// checks for was perfectly plausible in the file you would open to inspect it:
//
//   · The homepage declared `openGraph` with a title and a description and looked complete. A
//     page-level openGraph object REPLACES the parent's file-convention image rather than
//     merging, so it published no share card at all — on the most-linked URL on the site.
//   · A page declares a title string. Whether it survives a search result depends on its
//     RENDERED length, and 28 of 47 were over budget.
//   · The four auth routes each looked fine individually. As a set they published byte-identical
//     titles and descriptions, because a "use client" page cannot export metadata and they all
//     fell through to the same defaults.
//   · /solutions had zero inbound links and was missing from the sitemap. Nothing about the file
//     said so; only the route tree did.
//
// It lives in the `frontend` CI job, immediately after `npm run build`, because that is the only
// place the artifact exists. A Go test would have had to choose between skipping when unbuilt
// (ADR 0022 records a guard that did exactly that and printed ok for the rest of its life) and
// forcing a Node build into the Go job.
//
// IT FAILS RATHER THAN SKIPS. In this job the build has just run, so an empty page set means
// something is genuinely wrong — not that the checker has nothing to do.

import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";

const APP_DIR = join(process.cwd(), ".next", "server", "app");
const MARKETING_DIR = join(process.cwd(), "app", "(marketing)");

const TITLE_MAX = 60; // Google shows ~60 characters of a title
const DESC_MAX = 160; // ...and ~160 of a description

const problems = [];
const fail = (msg) => problems.push(msg);

// ---------------------------------------------------------------------------
// Collect the rendered pages.
// ---------------------------------------------------------------------------
if (!existsSync(APP_DIR)) {
  console.error(
    `check-seo: ${APP_DIR} does not exist. Run \`npm run build\` first.\n` +
      `Not skipping: a guard that excuses itself when it cannot find its input reports green forever.`,
  );
  process.exit(1);
}

/**
 * Every prerendered page, as { route, html } — walked RECURSIVELY.
 *
 * The first version of this read only the top level, which silently excluded
 * .next/server/app/frameworks/*.html and blog/*.html. Since the 25 framework pages are exactly
 * what carries the internal links into the blog, check 5 then reported all eight posts orphaned
 * when they were not. A guard reading a subset of its input reports confident nonsense, so this
 * is worth the recursion rather than a glob that looks close enough.
 */
function renderedPages(dir = APP_DIR, prefix = "") {
  const out = [];
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith("_")) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...renderedPages(full, `${prefix}${entry}/`));
      continue;
    }
    if (!entry.endsWith(".html")) continue;
    out.push({
      route: `${prefix}${entry.slice(0, -".html".length)}`,
      html: readFileSync(full, "utf8"),
    });
  }
  return out;
}

const unescape = (s) =>
  s
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&#x2014;/g, "—")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&"); // last: an entity's own & must not be re-decoded

const meta = (html, re) => {
  const m = html.match(re);
  return m ? unescape(m[1]) : null;
};

/**
 * The document head, with any inline <svg> stripped.
 *
 * EVERY document-level tag is read from HERE, never from the whole file, because `<title>` is
 * not unique to the head. An accessible inline SVG carries its own `<title>` as its accessible
 * name, and the brand mark renders twice per page (nav and footer) — so a built page holds
 * three `<title>` elements, of which only the first is the document's.
 *
 * The previous version matched the first `<title>` anywhere in the file. That returned the
 * right answer, but only because the head happens to be serialised before the body: it was
 * relying on document order, not on meaning. The failure that hides behind that is specific and
 * bad — a page missing its document title would have the "no <title>" check silently satisfied
 * by an SVG title reading "TensorShield", which is 12 characters and therefore also passes the
 * length check. A guard that cannot see a missing title is worse than no guard, because it
 * reports the absence as a pass.
 *
 * Found by probing the running dev server, where Next streams the document title into the BODY
 * and the SVG titles come first — so the same regex there returned "TensorShield". The built
 * output this script reads is ordered the other way, which is exactly why the bug was invisible
 * in CI.
 */
function documentHead(html, route) {
  const end = html.indexOf("</head>");
  if (end === -1) {
    // Anomalous for a built page. Report it rather than falling back to scanning the whole
    // document, which is how the original defect was introduced.
    fail(`${route}: no </head> in the rendered output — cannot read its metadata`);
    return "";
  }
  return html.slice(0, end).replace(/<svg[\s\S]*?<\/svg>/gi, "");
}

const pages = renderedPages().map((p) => {
  const head = documentHead(p.html, p.route);
  return {
    route: p.route,
    title: meta(head, /<title>([^<]*)<\/title>/),
    description: meta(head, /<meta name="description" content="([^"]*)"/),
    robots: meta(head, /<meta name="robots" content="([^"]*)"/) ?? "",
    ogImage: /<meta property="og:image"/.test(head),
    canonical: /<link rel="canonical"/.test(head),
    html: p.html, // the FULL document — check 5 counts links, which live in the body
  };
});

if (pages.length === 0) {
  console.error(`check-seo: found no prerendered pages in ${APP_DIR}. Refusing to report success.`);
  process.exit(1);
}

// A page is indexable unless it says otherwise. Indexability is the gate for every check below:
// a noindex page may legitimately be thin, duplicated, or canonical-less.
const indexable = pages.filter((p) => !p.robots.includes("noindex"));

// ---------------------------------------------------------------------------
// 1. Every indexable page publishes a share card and a canonical.
// ---------------------------------------------------------------------------
for (const p of indexable) {
  if (!p.ogImage) fail(`${p.route}: no og:image — a shared link unfurls as bare text`);
  if (!p.canonical) fail(`${p.route}: no canonical`);
  if (!p.title) fail(`${p.route}: no <title>`);
  if (!p.description) fail(`${p.route}: no meta description`);
}

// ---------------------------------------------------------------------------
// 2. Lengths, measured on UNESCAPED text.
//
// Reading them off raw HTML inflates every title containing an "&" by four characters, which
// is how the worst case first measured 114 instead of 110.
// ---------------------------------------------------------------------------
for (const p of indexable) {
  if (p.title && p.title.length > TITLE_MAX) {
    fail(`${p.route}: title is ${p.title.length} chars (max ${TITLE_MAX}) — "${p.title}"`);
  }
  if (p.description && p.description.length > DESC_MAX) {
    fail(`${p.route}: description is ${p.description.length} chars (max ${DESC_MAX})`);
  }
}

// ---------------------------------------------------------------------------
// 3. No two indexable pages compete with each other.
// ---------------------------------------------------------------------------
for (const [field, label] of [
  ["title", "title"],
  ["description", "description"],
]) {
  const seen = new Map();
  for (const p of indexable) {
    if (!p[field]) continue;
    const list = seen.get(p[field]) ?? [];
    list.push(p.route);
    seen.set(p[field], list);
  }
  for (const [value, routes] of seen) {
    if (routes.length > 1) {
      fail(
        `${routes.join(", ")} publish an identical ${label} — they compete with each other.\n` +
          `    "${value.slice(0, 90)}${value.length > 90 ? "…" : ""}"`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// 4. Every concrete marketing route is in the sitemap.
// ---------------------------------------------------------------------------
function marketingRoutes(dir = MARKETING_DIR, prefix = "") {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (entry === "page.tsx") {
      out.push(prefix);
      continue;
    }
    if (!statSync(full).isDirectory()) continue;
    if (entry.startsWith("[") || entry.startsWith("_") || entry.startsWith(".")) continue;
    const segment = entry.startsWith("(") && entry.endsWith(")") ? prefix : `${prefix}/${entry}`;
    out.push(...marketingRoutes(full, segment));
  }
  return out;
}

const sitemapPath = join(APP_DIR, "sitemap.xml.body");
if (!existsSync(sitemapPath)) {
  fail("no sitemap.xml was rendered");
} else {
  const xml = readFileSync(sitemapPath, "utf8");
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);

  // EVERY <loc> MUST BE ABSOLUTE. The sitemap protocol requires it and crawlers reject a relative
  // one, so this failure de-lists the whole site while the file still looks populated — which is
  // why the route-coverage check below cannot catch it: it strips the origin before comparing, so
  // it passes just as happily when there was no origin to strip.
  //
  // The live cause: SITE_URL fell back with `??`, which only catches null/undefined. An unset
  // GitHub repo variable passed as `--build-arg X=${vars.X}` arrives as an EMPTY STRING, so the
  // fallback did not fire and every URL lost its host. Verified with a real docker build.
  const relative = locs.filter((u) => !/^https?:\/\//.test(u));
  if (relative.length > 0) {
    fail(
      `${relative.length} sitemap URL(s) are not absolute (e.g. "${relative[0]}"). The sitemap ` +
        `protocol requires absolute URLs; a crawler discards this file. Check NEXT_PUBLIC_SITE_URL ` +
        `reached the build — an empty value is not the same as an unset one.`,
    );
  }

  const paths = new Set(locs.map((u) => u.replace(/^https?:\/\/[^/]+/, "")));
  for (const r of marketingRoutes()) {
    if (!paths.has(r)) {
      fail(`${r || "/"} is a real route but is not in sitemap.xml — nothing can discover it`);
    }
  }
}

// ---------------------------------------------------------------------------
// 5. Every blog post is reachable from something other than the blog index.
//
// This is the one that catches a starvation bug rather than a missing tag. `POSTS.slice(0, 4)`
// on 25 framework pages meant the four oldest posts had 26 inbound links each and the four
// newest had one — every new post structurally invisible to the largest block of internal
// links on the site, and nothing about that was visible in any single file.
// ---------------------------------------------------------------------------
const inbound = new Map();
for (const p of pages) {
  if (p.route === "blog") continue; // the index links to everything by construction
  for (const m of p.html.matchAll(/href="(\/blog\/[^"#?]+)"/g)) {
    inbound.set(m[1], (inbound.get(m[1]) ?? 0) + 1);
  }
}
const postSlugs = [...readdirSync(join(APP_DIR, "blog")).filter((f) => f.endsWith(".html"))].map(
  (f) => `/blog/${f.slice(0, -".html".length)}`,
);
for (const slug of postSlugs) {
  if (!inbound.get(slug)) {
    fail(`${slug} has no inbound link from any page except the blog index`);
  }
}

// ---------------------------------------------------------------------------
if (problems.length > 0) {
  console.error(`check-seo: ${problems.length} problem(s) across ${pages.length} rendered pages\n`);
  for (const p of problems) console.error(`  ✗ ${p}`);
  console.error(`\nSee docs/adr/0023-marketing-surface-ownership.md for why each of these is checked.`);
  process.exit(1);
}

console.log(
  `check-seo: ok — ${pages.length} rendered pages, ${indexable.length} indexable, ` +
    `${postSlugs.length} posts all reachable.`,
);
