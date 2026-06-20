import type { Metadata } from "next";

// The dynamic OG card (app/opengraph-image.tsx). It must be named explicitly here because a
// page-level `openGraph` object overrides — rather than inherits — the root segment's
// file-convention image, so without this every share card would lose its image. The route
// returns the PNG regardless of the cache-bust hash Next would otherwise append.
const OG_IMAGE = {
  url: "/opengraph-image",
  width: 1200,
  height: 630,
  alt: "TensorShield — your fractional AI security team",
  type: "image/png",
} as const;

// pageMeta builds the metadata for a public marketing route: title + description, a
// self-referential canonical URL (prevents duplicate-content dilution), and per-page
// OpenGraph + Twitter so a shared link unfurls with THIS page's title — not the site
// default. `path` is a root-relative path (e.g. "/pricing"); metadataBase (set in the root
// layout) resolves it and the image to absolute URLs.
export function pageMeta({
  title,
  description,
  path,
}: {
  title: string;
  description: string;
  path: string;
}): Metadata {
  return {
    title,
    description,
    alternates: { canonical: path },
    openGraph: {
      type: "website",
      siteName: "TensorShield",
      locale: "en_US",
      url: path,
      title,
      description,
      images: [OG_IMAGE],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [OG_IMAGE.url],
    },
  };
}
