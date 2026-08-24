// Canonical public site URL — used for sitemap/robots/canonical absolute URLs. Override per
// deploy with NEXT_PUBLIC_SITE_URL; the default is a placeholder for local/preview builds.
// `?.trim() ||`, NOT `??`. An unset GitHub repo variable passed as `--build-arg X=${{ vars.X }}`
// arrives as an EMPTY STRING, not as undefined — verified with a real docker build: an ARG never
// passed gives `undefined` (so `??` fires), an ARG passed empty gives `""` (so `??` does not).
// SITE_URL then became "" and every absolute URL on the site turned relative: the sitemap emitted
// <loc>/pricing</loc>, which the sitemap protocol forbids and crawlers reject, and robots.txt
// advertised `Sitemap: /sitemap.xml` with an empty Host. lib/contact.ts already guards this way.
export const SITE_URL = (process.env.NEXT_PUBLIC_SITE_URL?.trim() || "https://tensorshield.in").replace(/\/$/, "");

// ---------------------------------------------------------------------------
// Legal identity — THE ONE PLACE to set who is legally publishing this service.
//
// The Terms and Privacy pages are binding documents. They used to carry literal
// "[legal entity name]" and "[city]" placeholders in production copy, which is worse than
// wrong: an agreement that does not name a contracting party or a forum is unenforceable
// and signals an unfinished product to any buyer who reads it.
//
// These are build-time public values (they appear verbatim in published pages), so they are
// NEXT_PUBLIC_* env vars with honest fallbacks. `LEGAL_ENTITY_CONFIGURED` reports whether the
// deploy actually set them, so pages/preflight can refuse to present unconfigured legal text
// as final rather than silently shipping a placeholder.
// ---------------------------------------------------------------------------

/** Registered legal entity, e.g. "Tensorshield Technologies Pvt Ltd". */
export const LEGAL_ENTITY = process.env.NEXT_PUBLIC_LEGAL_ENTITY?.trim() || "";

/** Jurisdiction city whose courts have exclusive jurisdiction, e.g. "Bengaluru". */
export const LEGAL_JURISDICTION_CITY = process.env.NEXT_PUBLIC_LEGAL_JURISDICTION_CITY?.trim() || "";

/** Country of incorporation. Defaulted because the docs are already written around India. */
export const LEGAL_COUNTRY = process.env.NEXT_PUBLIC_LEGAL_COUNTRY?.trim() || "India";

/** Registered office address, shown in the legal docs' contact section when set. */
export const LEGAL_ADDRESS = process.env.NEXT_PUBLIC_LEGAL_ADDRESS?.trim() || "";

/** The email delivery provider acting as a subprocessor (GDPR Art. 28(2) requires naming it). */
export const SMTP_SUBPROCESSOR = process.env.NEXT_PUBLIC_SMTP_SUBPROCESSOR?.trim() || "";

/** True only when the deploy has supplied the legally load-bearing values. */
export const LEGAL_ENTITY_CONFIGURED = LEGAL_ENTITY !== "" && LEGAL_JURISDICTION_CITY !== "";

/**
 * The contracting party as it should read inline, e.g.
 *   "TensorShield (Acme Technologies Pvt Ltd, India)".
 * When unconfigured it degrades to the plain brand name rather than emitting a bracketed
 * placeholder — an incomplete sentence is better than a fake-looking legal claim.
 */
export function legalPartyName(): string {
  return LEGAL_ENTITY ? `TensorShield (${LEGAL_ENTITY}, ${LEGAL_COUNTRY})` : "TensorShield";
}

/** Governing-law sentence; omits the forum clause entirely when no city is configured. */
// The address is a REQUIRED argument, not a default spelled out here. lib/contact.ts is
// the single source for every address, and it reads SITE_URL from this file — so a
// default here would make the two modules import each other. The one caller passes
// LEGAL_EMAIL; the cycle stays broken and the address still lives in one place.
export function governingLawSentence(contactEmail: string): string {
  const base = `These Terms are governed by the laws of ${LEGAL_COUNTRY}`;
  const forum = LEGAL_JURISDICTION_CITY
    ? `, with exclusive jurisdiction in the courts of ${LEGAL_JURISDICTION_CITY}`
    : "";
  return `${base}${forum}. Questions: ${contactEmail}.`;
}
