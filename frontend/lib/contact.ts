import { SITE_URL } from "@/lib/site";

// ---------------------------------------------------------------------------
// HOW A CUSTOMER REACHES US — the single place every contact detail is set.
//
// Before this module the answer was scattered and incomplete. An audit of the
// whole marketing surface found:
//
//   · NO phone number anywhere on the site.
//   · NO /contact page, and no contact link in the nav or footer.
//   · Every "Talk to us", "Contact sales" and "Book a demo" CTA on nine pages
//     funnelled to ONE lead form. If it failed, or a visitor simply preferred
//     email, the site offered no other way to reach a human.
//   · The only published addresses were privacy@ and legal@, buried in legal
//     documents, hardcoded at six call sites.
//   · public/.well-known/security.txt hardcoded a THIRD address plus three
//     tensorshield.io URLs, while SITE_URL defaults to tensorshield.com — a
//     domain split that no single edit could fix.
//
// Everything below is a NEXT_PUBLIC_* build-time value, the same mechanism the
// legal identity in lib/site.ts already uses, so a deploy sets it once.
//
// GROUNDING (CLAUDE.md §10): an address or number that is not configured is NOT
// invented and NOT rendered. Publishing hello@ or a placeholder number that
// bounces is worse than publishing nothing, for the same reason the threat-intel
// ingest drops an advisory link that is not a real URL — a channel that does not
// reach anyone is worse than an honestly absent one. Callers check the
// `*_CONFIGURED` flags and fall back to the channel that does work.
// ---------------------------------------------------------------------------

/** The bare host from SITE_URL — "tensorshield.com" — so role addresses follow the site. */
export const SITE_HOST = SITE_URL.replace(/^https?:\/\//, "").replace(/\/.*$/, "");

const env = (v: string | undefined) => v?.trim() || "";

/**
 * General enquiries / sales. Unset by default ON PURPOSE: there is no way to
 * guess a real mailbox, and a published address that bounces costs more trust
 * than it wins. Set NEXT_PUBLIC_CONTACT_EMAIL to switch it on everywhere.
 */
export const CONTACT_EMAIL = env(process.env.NEXT_PUBLIC_CONTACT_EMAIL);

/**
 * Phone, as a human would read it — e.g. "+91 80 4718 2100". Unset by default,
 * same reasoning.
 */
export const CONTACT_PHONE = env(process.env.NEXT_PUBLIC_CONTACT_PHONE);

/**
 * The same number for a `tel:` href. Derived by stripping everything a dialler
 * cannot use, so nobody has to keep two formats in step; override only if the
 * dialable form genuinely differs (an extension, say).
 */
export const CONTACT_PHONE_TEL =
  env(process.env.NEXT_PUBLIC_CONTACT_PHONE_TEL) || CONTACT_PHONE.replace(/[^\d+]/g, "");

// The three role addresses that were ALREADY published on the site. Their defaults
// are the values that were hardcoded, so this module changes where they are edited,
// not what they say.
export const PRIVACY_EMAIL = env(process.env.NEXT_PUBLIC_PRIVACY_EMAIL) || `privacy@${SITE_HOST}`;
export const SECURITY_EMAIL = env(process.env.NEXT_PUBLIC_SECURITY_EMAIL) || `security@${SITE_HOST}`;
export const LEGAL_EMAIL = env(process.env.NEXT_PUBLIC_LEGAL_EMAIL) || `legal@${SITE_HOST}`;

/** True when a deploy has supplied a general contact address. */
export const CONTACT_EMAIL_CONFIGURED = CONTACT_EMAIL !== "";
/** True when a deploy has supplied a phone number. */
export const CONTACT_PHONE_CONFIGURED = CONTACT_PHONE !== "";
/** True when at least one direct channel is publishable. */
export const CONTACT_CONFIGURED = CONTACT_EMAIL_CONFIGURED || CONTACT_PHONE_CONFIGURED;

/**
 * Every channel worth showing a customer, in the order a page should offer them.
 *
 * Role addresses are always present because they were always published. The general
 * address and the phone appear only when configured — so a page renders whatever is
 * real and never a gap where a channel should be.
 */
export type Channel = {
  kind: "email" | "phone";
  label: string;
  value: string;
  href: string;
  /** What this channel is for, so a visitor picks the right one first time. */
  detail: string;
};

export function contactChannels(): Channel[] {
  const out: Channel[] = [];
  if (CONTACT_EMAIL_CONFIGURED) {
    out.push({
      kind: "email",
      label: "General & sales",
      value: CONTACT_EMAIL,
      href: `mailto:${CONTACT_EMAIL}`,
      detail: "Pricing, a demo, or anything that isn't urgent.",
    });
  }
  if (CONTACT_PHONE_CONFIGURED) {
    out.push({
      kind: "phone",
      label: "Phone",
      value: CONTACT_PHONE,
      href: `tel:${CONTACT_PHONE_TEL}`,
      detail: "Business hours, India Standard Time.",
    });
  }
  out.push(
    {
      kind: "email",
      label: "Security",
      value: SECURITY_EMAIL,
      href: `mailto:${SECURITY_EMAIL}`,
      detail: "Report a vulnerability in our product or infrastructure.",
    },
    {
      kind: "email",
      label: "Privacy",
      value: PRIVACY_EMAIL,
      href: `mailto:${PRIVACY_EMAIL}`,
      detail: "Data-protection requests, DPAs and subprocessor questions.",
    },
    {
      kind: "email",
      label: "Legal",
      value: LEGAL_EMAIL,
      href: `mailto:${LEGAL_EMAIL}`,
      detail: "Contracts and anything about our terms.",
    },
  );
  return out;
}
