import type { Metadata } from "next";

// The dynamic OG card (app/opengraph-image.tsx). It must be named explicitly here because a
// page-level `openGraph` object overrides — rather than inherits — the root segment's
// file-convention image, so without this every share card would lose its image. The route
// returns the PNG regardless of the cache-bust hash Next would otherwise append.
//
// That is not hypothetical: the homepage was the one route that hand-rolled `openGraph`
// instead of calling pageMeta(), and it published no og:image at all — the single most-shared
// URL on the site, unfurling as bare text. This comment sat six lines from the fix and stopped
// nothing, because nothing compared what the pages published. See ADR 0023.
const OG_IMAGE = {
  url: "/opengraph-image",
  width: 1200,
  height: 630,
  alt: "TensorShield — your fractional AI security team",
  type: "image/png",
} as const;

/**
 * pageMeta builds the metadata for a public marketing route.
 *
 * **`title` is the BARE title — do not append "| TensorShield".** The root layout owns the
 * brand suffix via `title.template` (app/layout.tsx), so passing it here would double it.
 * Before that template existed all 47 pages hand-typed the suffix, in two different styles
 * (31 `|`, 11 `—`), each spending ~15 of the ~60 characters a search result shows. ADR 0023
 * decision 1.
 *
 * The social title deliberately does NOT carry the suffix either: `og:site_name` already
 * says TensorShield, so repeating it in `og:title` spends the card's headline on the brand.
 *
 * @param title       Bare page title, no brand suffix. Aim ≤ 45 chars so title + suffix ≤ 60.
 * @param description Meta description. Front-load it — only ~160 chars are shown.
 * @param path        Root-relative path (e.g. "/pricing"); metadataBase resolves it absolute.
 * @param socialTitle       Optional. A punchier headline for the share card only.
 * @param socialDescription Optional. Social has more room than a SERP snippet does.
 */
export function pageMeta({
  title,
  description,
  path,
  socialTitle,
  socialDescription,
}: {
  title: string;
  description: string;
  path: string;
  socialTitle?: string;
  socialDescription?: string;
}): Metadata {
  const ogTitle = socialTitle ?? title;
  const ogDescription = socialDescription ?? description;
  return {
    title,
    description,
    alternates: { canonical: path },
    openGraph: {
      type: "website",
      siteName: "TensorShield",
      locale: "en_US",
      url: path,
      title: ogTitle,
      description: ogDescription,
      images: [OG_IMAGE],
    },
    twitter: {
      card: "summary_large_image",
      title: ogTitle,
      description: ogDescription,
      images: [OG_IMAGE.url],
    },
  };
}

/**
 * noIndex marks a route that must never appear in search results — an authenticated or
 * transactional page with no search value.
 *
 * It exists so indexability is a DECISION each such route makes, rather than something
 * inherited: the four auth routes were `index, follow` purely because they declared no
 * metadata and fell through to the root layout's marketing default, which left four
 * byte-identical thin pages competing with the homepage on the brand query. ADR 0023
 * decision 3.
 *
 * `follow` stays true so link equity still flows through to whatever these pages link to.
 */
export function noIndex(title: string, description: string): Metadata {
  return {
    title,
    description,
    robots: { index: false, follow: true },
  };
}
