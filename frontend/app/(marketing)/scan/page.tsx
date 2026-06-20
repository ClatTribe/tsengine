import { ScanForm } from "@/components/marketing/scan-form";
import { pageMeta } from "@/lib/seo";

export const metadata = pageMeta({
  title: "Free Email Security Check — Is Your Domain Spoofable? | TensorShield",
  description:
    "Instantly check your domain's email-auth posture (DMARC, SPF, DKIM) for free — no signup. See if attackers can spoof your domain for phishing, and get a security grade in seconds.",
  path: "/scan",
});

export default function ScanPage() {
  return (
    <section className="relative overflow-hidden">
      <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
      <div className="relative mx-auto max-w-3xl px-5 pb-24 pt-20 text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">Free · no signup</span>
        <h1 className="mx-auto mt-3 max-w-2xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
          Can attackers spoof your domain?
        </h1>
        <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
          Enter your domain for an instant, read-only check of its email authentication (DMARC, SPF, DKIM) — the #1
          gap behind phishing and business-email-compromise. Get a grade in seconds.
        </p>
        <div className="mt-8">
          <ScanForm />
        </div>
      </div>
    </section>
  );
}
