import Link from "next/link";
import { Mail, Phone, ArrowRight } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { contactChannels, CONTACT_CONFIGURED } from "@/lib/contact";

// The page that did not exist. Every "Talk to us", "Contact sales" and "Book a demo" CTA on the
// site pointed at one lead form, so a visitor who wanted to email or call a human had nowhere to
// go — and the only published addresses were buried in the privacy policy.
//
// Every channel comes from lib/contact.ts. Nothing here is typed twice.
export const metadata = pageMeta({
  title: "Contact us",
  description:
    "Email us, call us, or book a demo. Security and privacy have their own addresses, so your message reaches the right person first time.",
  path: "/contact",
});

export default function ContactPage() {
  const channels = contactChannels();

  return (
    <section className="relative overflow-hidden">
      <AuroraBackdrop />
      <div className="relative mx-auto max-w-4xl animate-fade-rise px-5 pb-24 pt-20">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">Contact</span>
        <h1 className="mt-3 text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
          Talk to a human
        </h1>
        <p className="mt-4 max-w-xl text-lg leading-relaxed text-muted">
          {CONTACT_CONFIGURED
            ? "Email or call us directly, or book a demo and we'll walk you through it. Security and privacy have their own addresses so your message lands with the right person."
            : "Book a demo and we'll walk you through it. Security and privacy reports have their own addresses so they reach the right person straight away."}
        </p>

        <div className="mt-10 grid gap-3 sm:grid-cols-2">
          {channels.map((c) => (
            <a
              key={c.label}
              href={c.href}
              className="group card flex items-start gap-3 p-5 transition hover:shadow-card-hover"
            >
              <span className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                {c.kind === "phone" ? <Phone className="h-4 w-4" /> : <Mail className="h-4 w-4" />}
              </span>
              <span className="min-w-0">
                <span className="block text-xs font-semibold uppercase tracking-wider text-faint">
                  {c.label}
                </span>
                <span className="mt-1 block break-words font-medium text-ink group-hover:text-accent">
                  {c.value}
                </span>
                <span className="mt-1 block text-sm leading-relaxed text-muted">{c.detail}</span>
              </span>
            </a>
          ))}
        </div>

        <div className="mt-10 rounded-2xl border border-accent/30 bg-accent-soft/30 p-6">
          <p className="text-sm font-medium text-ink">
            Want to see it running against your own systems first?
          </p>
          <p className="mt-1 text-sm leading-relaxed text-muted">
            Book a demo and we&apos;ll tailor it to what your customers and auditors are asking
            for — or check your domain free, with no signup and nothing to install.
          </p>
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Link
              href="/demo"
              className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
            >
              Book a demo <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/scan" className="text-sm font-medium text-accent hover:underline">
              or check your domain — free, no signup
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
