# ADR 0023 — The marketing surface is correct everywhere it is generated and wrong everywhere it is typed

**Status:** Accepted · all seven decisions implemented (56b74b2, ef94657, 2db417f, 531b417).
The three questions in §Open are still unanswered and are not blocked on any of them.
**Date:** 2026-08-22

> **Implementation note.** Building decision 7 showed that the audits behind this ADR had been
> reading a subset of the site. Both scanned only the top level of `.next/server/app`, so the
> 25 framework pages, 8 blog posts and 2 resources — 35 of 82 rendered pages — were never
> length-checked. The guard walks recursively and reported 47 further problems on its first
> run, all real. The counts in §What was measured are left as they were recorded; they
> understated the problem, and the correction is the point.

## Context

Two audits of the public marketing surface, run separately and a day apart, returned 13 and
10 findings respectively. Ranked by cost they look unrelated — a missing share image, titles
that are too long, four indexable login pages, a blog post promising a scan we do not run,
a related-reading block frozen on its four oldest articles.

They are one finding. In every case a value that **could be computed from a source of truth
was typed by hand instead**, and nothing compared the two.

Where the surface generates, it is right. `lib/seo.ts`'s `pageMeta()` produces a
self-referential canonical, per-page OpenGraph and Twitter cards and an explicit card image
for **46 of 47 marketing routes**, and on those 46 routes there is nothing to fix. Every
defect below sits at a place that opted out of a generator, or never had one.

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

### The same shape, found again in the blog

A separate review of all 8 posts was run afterwards. It is recorded here rather than
separately because three of its findings are this ADR's thesis in different clothes, and the
fourth is a failure mode the metadata audit could not have surfaced.

**`readMins` is typed.** It is wrong on all eight posts, always in the same direction, and by
up to 3.7×: a 351-word post is labelled "5 min read". It is rendered twice — on the index
card and under the post title — so it is the first promise each post makes and the easiest
one for a reader to check. A word count over 225 is not a judgement call; it is a function of
the body that someone is retyping.

**The related-posts block is `POSTS.slice(0, 4)`.** Each of the 25 framework pages ends with
"Reading on getting audit-ready" built from the first four entries of an array ordered
oldest-first. It is the sitemap's `staticPaths` problem with a different surface: something
that looks derived but is pinned to an accident of ordering, so it can only ever recommend
the four oldest posts no matter how many are published. The effect is measured and inverted —
the four posts it favours have **26 inbound links each**, and the four newest and longest
have **one**. It is also identical on every framework page, so the ISO 42001 page and the PCI
page recommend the same four articles under a heading claiming relevance.

**The content model cannot express a link.** `Block` is `p | h2 | ul | cta`, and the renderer
emits `{b.text}` as an escaped React text child, so a paragraph cannot contain a link even if
someone wrote one. All 15 hrefs in the blog are full-width CTA buttons pointing at product
pages, and **no post links to another post**. This is not an omission an author can fix. It is
expensive here specifically because these eight posts already cross-reference each other in
prose — the DPDP post states that its breach duty differs from CERT-In's, and there is a
CERT-In post — so every link the reader wants and the crawler would use is one the type
forbids.

**And one genuinely new failure mode.** `pass-enterprise-security-questionnaire` lists five
checks and says: *"Our free scanner runs **exactly these** read-only checks against your
domain."* It runs four. `/v1/assess` emits eight checks — DMARC, SPF, DKIM, HTTPS enforced,
HSTS, CSP, clickjacking/MIME, security.txt — and none inspects dependencies, which requires a
connected repository. The fifth bullet is not externally detectable at all, so the post's own
framing is wrong before its claim about our scanner is.

This one is not an SEO defect and it is worse than the others, because of the direction it
fails in. A founder runs the free scan, sees a grade with no dependency finding in it, and
concludes their dependencies are clean. **That is the false-clean result the entire engine is
built to prevent** — §10 grounding, `asset.CoverageRulePrefix`, the rule that a check which
did not run must never render as one that passed — arriving through marketing copy instead of
through a scanner. The check list is a definite, enumerable set that exists in code, and a
blog post restated it from memory.

### What the same passes found in good shape

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
- **The blog's regulatory content is accurate**, which matters because it is the highest-risk
  copy on the site. CERT-In's six-hour clock (from *noticing*, not confirming), 180-day log
  retention held in India, NIC/NPL clock sync and five-year KYC retention all check out; DPDP's
  Fiduciary/Processor distinction is applied correctly to the B2B case, including the
  non-obvious point that its breach duty is separate from CERT-In's; SOC 2 is described as an
  attestation with no pass mark rather than a certification. **The plan claims check out too** —
  `AllFrameworks` really is `true` on the Free tier, so "all 25 frameworks, free" is accurate
  rather than a bait CTA. Finding 8's decision below is narrow on purpose: one enumeration is
  wrong, not the blog's factual standard.

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

### 4. A value that is a function of the content is computed from the content

The generalisation of the rule `app/sitemap.ts` already states for `POSTS` and
`RESOURCE_LIST`, applied to the three places that still type it:

| today | becomes |
|---|---|
| `staticPaths[]` hand-listed in `sitemap.ts` | derived from the route tree; add `lastMod` where a real date exists |
| `readMins` typed per post | word count over 225, computed at build |
| `POSTS.slice(0, 4)` on 25 framework pages | selected by relevance (category or tag), falling back to most-recent |

These read as three chores and are one rule. Fixing them individually — adding the three
missing routes, correcting eight read times, hand-picking four posts — fixes today and
re-arms every one of them. `changefreq`/`priority` may stay in the sitemap; they cost nothing
and do nothing.

### 5. The blog can link to the blog

`Block` gains a way to express an inline link, or — the cheaper version that captures most of
the value — `Post` gains a `related: string[]` rendered as a Related-reading block.

Internal linking between related articles is the main mechanism by which a small blog builds
topical authority, and eight posts on one coherent theme with no links between them read to a
crawler as eight unrelated pages. This is a type change rather than a content change, which is
why it is a decision and not a task: no amount of editing fixes it.

### 6. Marketing copy does not enumerate a product capability it has not read from the product

Prose cannot be statically verified against behaviour, and this decision does not pretend
otherwise. What it requires is narrower and achievable:

- The set of checks `/v1/assess` runs is **pinned by a test** that names the surfaces
  describing it — the blog post, `/scan`, the badge. Adding or removing a check then fails a
  test whose message says which copy to go update. This is the same "pin the one line that
  decides" pattern already used on the threat-intel path.
- Where a capability list is short and stable, the page **renders it from the source** rather
  than restating it.

The failure this prevents is not embarrassment, it is a false all-clear. A customer-facing
claim that we check something we do not check is the same defect class as a scanner reporting
a skipped check as passed, and §10 does not stop applying because the sentence is in a blog
post.

### 7. A guard over the BUILT output, not over the source

The four highest-cost metadata findings are all invisible in source and all trivially
detectable in the rendered HTML. Add a check — the marketing-surface twin of
`internal/uicheck` — that parses `.next/server/app/*.html` after a build and fails on:

| assertion | catches |
|---|---|
| every indexable page has `og:image` and `canonical` | the homepage card |
| no two indexable pages share a title or a description | the four auth routes |
| title ≤ 60 and description ≤ 160, on unescaped text | 28 and 37 pages respectively |
| every non-dynamic marketing route appears in `sitemap.xml` | `/solutions`, `/docs` |
| every post is reachable from at least one non-index page | the `slice(0, 4)` starvation |

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
4. **Nothing that can be computed from the content is stored beside it.** Routes, read times
   and related-post selections are derived; a hand-maintained list of any of them is the
   defect, not the drift it later produces.
5. **A published claim about what a product surface checks is traceable to the code that
   checks it.** Where the list is enumerable, it is pinned or rendered.
6. **The audited artifact is the rendered page, not the source.** Any future check of what
   this site publishes reads the built HTML — every defect that motivated this ADR was
   perfectly plausible in source.

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

**This is a small change with a disproportionate headline.** The metadata fixes are roughly
half a day and cover everything actually broken; decisions 6 and 7 are the part worth more
than the fixes, because they convert "we checked the marketing surface once" into a property
of the build.

**Decision 1 will look like churn in the diff.** Forty-seven title strings change and no
rendered title changes except in length. That is the point — the edit is mechanical
precisely because the suffix was never page-specific information.

**Decision 4 will re-rank the blog on its own.** Selecting related posts by relevance moves
25 pages' worth of internal links off the three shortest, oldest articles and onto the ones
worth reading. No content has to change for that to happen, which is the argument for doing
it before any editorial work.

**Editorial strategy is deliberately absent from this ADR**, and it was the largest finding
in the blog review. The posts written since 12 August are two to three times longer than the
June set, target queries the compliance incumbents have no reason to cover, and are aimed
squarely at the ICP; the June posts compete head-on with Vanta and Drata on their strongest
queries at 350 words. That is a content decision for whoever owns the blog, not an
architectural one, and writing it down as a decision here would give it a formality it has
not earned. The same applies to the two cannibalising pairs, the single-member categories,
and the absent author byline.

**Also logged as work rather than architecture**: `BlogPosting` is missing `image` and
`dateModified`, no page emits `BreadcrumbList` despite three genuine hierarchies, four pages
skip from `h1` to `h3`, and one post argues for continuous monitoring while linking to a plan
where `ContinuousMonitoring` is `false`. None needs a rule; they need doing.

**What this ADR does not cover.** It audits what the code publishes. It says nothing about
what is *ranking*, or about which posts anyone reads — there is no Search Console, analytics,
backlink or field-CWV data in this repo, and no confirmation that the live site serves what
this build produces. A green guard means the pages we ship are well-formed, never that they
perform.
