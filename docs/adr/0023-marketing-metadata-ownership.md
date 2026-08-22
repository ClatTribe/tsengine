# ADR 0023 — The marketing site's metadata is correct everywhere it is generated and wrong everywhere it is typed

**Status:** Proposed · two decisions below need an answer that is not in the repo (§Open)
**Date:** 2026-08-22

## Context

An SEO audit of the public marketing surface — 47 routes, measured from the **built HTML**
in `.next/server/app` plus the generated `robots.txt` and `sitemap.xml` — returned 13
findings. Ranked by cost they look unrelated: a missing share image, titles that are too
long, four indexable login pages, a page nothing links to. They are not unrelated. Every
one of them sits at a place that **opted out of, or was never brought under, the one helper
that already does this correctly**:

> `lib/seo.ts` `pageMeta()` produces a self-referential canonical, per-page OpenGraph and
> Twitter cards, and an explicit card image, for **46 of 47 marketing routes**. On those 46
> routes there is nothing to fix.

The system is right. The exceptions are wrong. And the exceptions are invisible from the
file you would open to check them.

### The shape these defects share

Reading `app/(marketing)/page.tsx` you see a `title`, a `description`, a `canonical`, an
`openGraph` block with a title and a description. It looks complete. It is the only page on
the site that publishes no share image, because in Next's metadata model a page-level
`openGraph` object **replaces** the parent segment's file-convention image rather than
merging with it — so declaring `openGraph` without `images` deletes the card.

That merge rule is already documented in this repo. `lib/seo.ts` carries a comment
explaining it, which is *why* `pageMeta()` names `OG_IMAGE` explicitly. The homepage is the
one route that does not call `pageMeta()`, and it hit the exact failure the comment was
written to prevent. The comment was correct, sat six lines from the fix, and stopped
nothing — because nothing compared what the pages **published**.

The same shape produced the rest:

- **Title length is not visible in the source.** A page declares a string; whether it
  survives a search result depends on its rendered length, and 28 of 47 exceed the ~60
  characters Google shows. The longest is 110. Nobody typed "110 characters"; they typed a
  good title and then, as all 47 pages must, hand-typed the brand suffix onto the end of it.
- **Duplication is only visible across pages.** `/login`, `/signup`, `/forgot-password` and
  `/reset-password` declare no metadata at all, so all four inherit the root layout's
  defaults and publish **byte-identical titles and descriptions**, explicitly
  `index, follow`, with no canonical and no structured data. Each file is individually fine.
  The set is four thin duplicates competing with the homepage on the brand query.
- **Absence is only visible against the route tree.** `/solutions` has **zero inbound links
  from any prerendered page and is absent from the sitemap** — no path to it exists except
  typing the URL. `/docs` and `/agent-controls` are also missing from the sitemap.

### What was measured

```
47 marketing routes · 82 prerendered pages inspected
46/47   route through pageMeta()                  <- why most of this is small
28/47   titles over 60 chars      (max 110)
37/47   descriptions over 160     (max 374)
 1/82   missing og:image          -> the homepage, the most-linked URL on the site
 4/82   missing canonical         -> the four auth routes, all index,follow
 4       pages sharing one title AND one description
 0       inbound links to /solutions       0  BreadcrumbList on any page
76       sitemap URLs: 8 carry lastmod, 76 carry changefreq + priority
```

Lengths are measured on **unescaped** text. Reading them off the raw HTML inflates every
title containing an `&` by four characters and would have put the worst case at 114.

### Why the sitemap belongs in this ADR and not on a task list

`app/sitemap.ts` already states the correct rule, in its own comment:

> **"CONTENT ROUTES ARE DERIVED, NEVER HAND-LISTED."** … *"The hand-maintained list is what
> broke here … A derived list cannot drift out of sync with the content it describes."*

That comment was written after blog posts shipped without being submitted. The rule it
states is right, and it was applied to `POSTS` and `RESOURCE_LIST` only — the `staticPaths`
array immediately above it is still hand-maintained. Three routes have since drifted out of
it. The diagnosis was correct and the fix covered half the file.

Separately, the sitemap spends its signal backwards: all 76 URLs carry `changefreq` and
`priority`, which Google states it ignores, and 8 carry `lastmod`, which it uses.

### What the same pass found in good shape

Listed so this is not read as proposing work on things that are already right.

- **Structured data is strong.** `Organization`, `WebSite`, `SoftwareApplication` and
  `Offer` on all 78 public pages; `FAQPage` on 40; `BlogPosting` on 8. The 25 templated
  framework pages branch their FAQ on whether the framework is auditor-attested, so they are
  not thin duplicates of one another — and `dynamicParams = false` means an invented URL
  404s instead of generating an unbounded crawlable surface.
- **Every page has a title and a description**; none is too short. The problem is length in
  one direction only.
- **No missing image alt text, because there are no `<img>` tags** — every graphic is inline
  SVG carrying a `<title>`.
- **The two merged pages redirect permanently** (`/identity` → `/saas-posture`,
  `/supply-chain` → `/code-security`), consolidating link value instead of leaving two
  near-duplicates competing.
- **`NEXT_PUBLIC_*` are passed as Docker build args**, with a comment explaining why runtime
  env cannot work for them. Without that the entire canonical layer would publish a
  placeholder domain.

## Decision

### 1. The root layout owns the brand suffix; pages supply only the distinctive part

Set `title: { template: "%s | TensorShield", default: TITLE }` in `app/layout.tsx` and strip
the suffix from all 47 pages.

Today every page hand-types it, and they do not agree: **31 use `| TensorShield`, 11 use
`— TensorShield`**, and 5 work the name into the sentence. Each page pays ~15 characters of
a ~60-character budget for something a template appends for free, and pays it in two styles.
Centralising it recovers the budget and makes the inconsistency unrepresentable rather than
merely fixed. The ~12 titles still over budget after the suffix comes off get rewritten.

### 2. `pageMeta()` is the only way a marketing route declares metadata

No page hand-rolls `openGraph`. A route that needs a different social title passes it to the
helper; the helper keeps ownership of the image, the canonical and the Twitter block.

This is decision 1's principle applied to the second field: the defect was not that the
homepage author forgot `images`, it was that a route was *able* to declare a partial
`openGraph` and silently lose the card.

### 3. Indexability is declared, not inherited

Every route states whether it should be indexed. The four auth routes get
`robots: { index: false, follow: true }`.

They are currently indexable because nobody decided they should be — they inherit
`index, follow` from a root-layout default written for marketing pages. Inheriting an
indexing decision is how four duplicate pages end up competing for your own brand name.

### 4. The sitemap is derived from the route tree, never hand-listed

Extend the rule `app/sitemap.ts` already states to the `staticPaths` array it currently
exempts. Add `lastMod` where a real date exists; `changefreq`/`priority` may stay, they cost
nothing and do nothing.

This is the decision that keeps finding 5 fixed. Adding the three missing routes by hand
fixes today and re-arms the same trap.

### 5. A guard over the BUILT output, not over the source

The four highest-cost findings are all invisible in source and all trivially detectable in
the rendered HTML. Add a check — the marketing-surface twin of `internal/uicheck` — that
parses `.next/server/app/*.html` after a build and fails on:

| assertion | catches |
|---|---|
| every indexable page has `og:image` and `canonical` | the homepage card, finding 01 |
| no two indexable pages share a title or a description | the four auth routes, finding 04 |
| title ≤ 60 and description ≤ 160, on unescaped text | findings 02 and 03 |
| every non-dynamic marketing route appears in `sitemap.xml` | `/solutions`, `/docs`, finding 05 |

**The guard must fail hard when it cannot find the pages to check.** ADR 0022 records a
guard in this repo that looked for a block the codebase does not use, found nothing, called
`t.Skip`, and printed `ok` for the rest of its life. A metadata guard that cannot locate a
build is in exactly that position — if `.next` is absent it fails, it does not skip.

## Invariants

1. **A marketing route declares metadata through `pageMeta()` and through nothing else.**
   A partial `openGraph` object is not a thing a page may write.
2. **The brand suffix appears in exactly one file.** A title containing `TensorShield` in
   `app/(marketing)/**` is a build failure.
3. **Indexability is explicit per route.** Inheriting the layout default is not a decision.
4. **The sitemap is computed from the routes that exist**, in the same way `POSTS` and
   `RESOURCE_LIST` already are.
5. **The audited artifact is the rendered page, not the source.** Any future check of what
   this site publishes reads the built HTML — the four defects that motivated this ADR were
   each perfectly plausible in source.

## Open — these need an answer that is not in the repo

**Which domain is real.** `SITE_URL` defaults to `tensorshield.com` and is the value baked
into every canonical, every `og:url` and all 76 sitemap entries. Every contact address on
the site — privacy policy, DPA, subprocessors page, governing-law clause, six occurrences —
is `@tensorshield.io`. Only one can be right, and if the live site is the `.io` then every
canonical URL published points at a domain we do not own. This ADR does not pick one;
picking one from the code would be guessing at a fact about the business.

**Whether `/solutions` should exist.** It has zero inbound links and is not in the sitemap.
Link it and add it, or delete it and redirect it — both are correct, and the decision is a
product one about whether the page has a job.

**Where the marketing site lives relative to the app.** The prod build arg falls back
`NEXT_PUBLIC_SITE_URL` → `https://${TSENGINE_SITE_ADDRESS}` → `https://localhost`, and
`.env.example` ships `TSENGINE_SITE_ADDRESS=app.yourdomain.com` with `NEXT_PUBLIC_SITE_URL`
empty — which Compose treats as unset. An operator who fills in only the Caddy address gets
a working, correctly-certificated site whose every canonical declares the `app.` subdomain,
with nothing visibly broken. If marketing belongs on the apex, `.env.example` should set the
site URL rather than leave it to the fallback, and the preflight should refuse a build where
it resolves to an `app.` host or to localhost.

## Consequences

**This is a small change with a disproportionate headline.** Findings 01 through 04 are
roughly half a day and cover everything actually broken; decision 5 is the part that is
worth more than the fixes, because it converts "we checked the marketing metadata once" into
a property of the build.

**Decision 1 will look like churn in the diff.** Forty-seven title strings change and no
rendered title changes except in length. That is the point — the edit is mechanical
precisely because the suffix was never page-specific information.

**Three findings are deliberately not decided here**, and are logged as work rather than
architecture: `BlogPosting` is missing `image` and `dateModified` (which is what a per-post
OG route would supply), no page emits `BreadcrumbList` despite three genuine hierarchies,
and four pages skip from `h1` to `h3`. None of them needs a rule; they need doing.

**What this ADR does not cover.** It audits what the code publishes. It says nothing about
what is *ranking* — there is no Search Console, analytics, backlink or field-CWV data in
this repo, and no confirmation that the live site serves what this build produces. A green
guard means the pages we ship are well-formed, never that they perform.
