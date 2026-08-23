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
// GROUNDING (CLAUDE.md §10): a channel is published only when it is REAL. The
// general email and phone below are the owner's actual, monitored ones; nothing
// here is a plausible-looking guess. Publishing a hello@ that bounces is worse
// than publishing nothing, for the same reason the threat-intel ingest drops an
// advisory link that is not a real URL — a channel that reaches nobody is worse
// than an honestly absent one.
//
// The `*_CONFIGURED` flags and the conditional rendering stay: a deployment that
// genuinely has no phone (a US arm, a white-label) blanks the constant and every
// surface drops it cleanly, instead of rendering a label with nothing beside it.
// ---------------------------------------------------------------------------

/** The bare host from SITE_URL — "tensorshield.com" — so role addresses follow the site. */
export const SITE_HOST = SITE_URL.replace(/^https?:\/\//, "").replace(/\/.*$/, "");

const env = (v: string | undefined) => v?.trim() || "";

/**
 * General enquiries / sales. The default is the live, monitored mailbox — supplied
 * by the owner, not guessed, which is the whole condition for publishing one.
 * NEXT_PUBLIC_CONTACT_EMAIL overrides it per deploy.
 */
export const CONTACT_EMAIL = env(process.env.NEXT_PUBLIC_CONTACT_EMAIL) || "shieldtensor@gmail.com";

/**
 * Phone, as a human would read it. Same source, same rule.
 * NEXT_PUBLIC_CONTACT_PHONE overrides it per deploy.
 */
export const CONTACT_PHONE = env(process.env.NEXT_PUBLIC_CONTACT_PHONE) || "+91 80049 20400";

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
