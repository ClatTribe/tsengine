import { SECURITY_EMAIL } from "@/lib/contact";
import { SITE_URL } from "@/lib/site";

// security.txt (RFC 9116) — the address a researcher uses to report a vulnerability in OUR
// product, and one of the externally-visible checks our own free scanner runs against a
// customer's domain.
//
// It was a static file in public/, and it had drifted exactly the way a hand-maintained file
// does: it hardcoded a third contact address nothing else knew about, and three
// https://tensorshield.io URLs while SITE_URL said tensorshield.com — neither was the real domain
// (it is tensorshield.in; see ADR 0023). Generating it means the
// address comes from lib/contact.ts and the URLs from SITE_URL, so neither can disagree with
// the rest of the site again.
//
// `Expires` is required by RFC 9116 and must be in the future or the file is invalid. It is
// computed a year out at BUILD time rather than typed, so it cannot silently lapse — the old
// file carried a fixed 2027 date that would have expired with nobody watching.
export const dynamic = "force-static";

function oneYearOut(): string {
  const d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() + 1);
  d.setUTCHours(0, 0, 0, 0);
  return d.toISOString();
}

export function GET() {
  const body = [
    `# TensorShield security contact — ${SITE_URL}/security`,
    `Contact: mailto:${SECURITY_EMAIL}`,
    `Expires: ${oneYearOut()}`,
    "Preferred-Languages: en",
    `Canonical: ${SITE_URL}/.well-known/security.txt`,
    `Policy: ${SITE_URL}/security`,
    "",
  ].join("\n");

  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    },
  });
}
