import { CheckCircle2 } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { DemoForm } from "@/components/marketing/demo-form";

export const metadata = pageMeta({
  title: "Book a Demo — TensorShield",
  description: "See TensorShield run on your stack. Talk to our team about VAPT, compliance (SOC 2, ISO 27001, and 12 more), and autonomous remediation for your SMB.",
  path: "/demo",
});

const POINTS = [
  "A walkthrough on your real stack — code, cloud, and identity.",
  "How we map findings to 14 compliance frameworks with signed evidence.",
  "The VAPT / pentest report your enterprise customers ask for.",
  "How human-in-the-loop autonomy keeps you in control of every change.",
];

export default function DemoPage() {
  return (
    <section className="relative overflow-hidden">
      <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
      <div className="relative mx-auto grid max-w-5xl items-start gap-10 px-5 pb-24 pt-20 lg:grid-cols-2">
        <div>
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Talk to sales</span>
          <h1 className="mt-3 text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">Book a demo</h1>
          <p className="mt-4 max-w-md text-lg leading-relaxed text-muted">
            See your fractional security team in action. We&apos;ll tailor it to what your customers and auditors are
            asking for.
          </p>
          <ul className="mt-7 space-y-3">
            {POINTS.map((p) => (
              <li key={p} className="flex items-start gap-2.5 text-sm text-ink">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {p}
              </li>
            ))}
          </ul>
          <p className="mt-7 text-sm text-muted">
            Prefer to dive in yourself? <a href="/signup" className="font-semibold text-accent hover:underline">Start free</a> — no demo required.
          </p>
        </div>
        <DemoForm />
      </div>
    </section>
  );
}
