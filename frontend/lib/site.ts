// Canonical public site URL — used for sitemap/robots/canonical absolute URLs. Override per
// deploy with NEXT_PUBLIC_SITE_URL; the default is a placeholder for local/preview builds.
export const SITE_URL = (process.env.NEXT_PUBLIC_SITE_URL ?? "https://tensorshield.com").replace(/\/$/, "");
