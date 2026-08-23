import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";

import { ArrowRight, ShieldCheck } from "lucide-react";
import { FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_DESC, FRAMEWORK_CATEGORY, frameworkGroups, FRAMEWORK_COUNT } from "@/lib/frameworks";

export const metadata = pageMeta({
  title: "25 Compliance Frameworks — SOC 2, ISO, HIPAA",
  description:
    `${FRAMEWORK_COUNT} compliance frameworks — SOC 2, ISO 27001, PCI-DSS, HIPAA, NIST, GDPR, India DPDP and more — with continuous monitoring and signed evidence.`,
  path: "/frameworks",
});

export default function FrameworksIndex() {
  const groups = frameworkGroups();

  return (
    <>
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">{FRAMEWORKS.length} frameworks, automated</span>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">Compliance frameworks we automate</h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            One platform, {FRAMEWORKS.length} frameworks. Pick the one your customers ask for — TensorShield maps your
            findings to its controls, prepares the fixes, and produces signed, auditor-ready evidence.
          </p>
          {/* Pillar three, stated once and plainly: the evidence is a by-product of the security
              work, not a second project with its own tool and its own bill. */}
          <p className="mx-auto mt-4 max-w-xl text-base leading-relaxed text-ink">
            None of it is a separate exercise. The same work that finds and closes a real problem is what fills in the
            control — so compliance stops being a second project you run alongside security.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-6xl space-y-10 px-5 pb-16">
        {groups.map(({ cat, items }) => (
          <div key={cat}>
            <h2 className="mb-4 text-xs font-semibold uppercase tracking-wider text-faint">{cat}</h2>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {items.map((f) => (
                <Link key={f} href={`/frameworks/${f}`} className="group card p-5 transition hover:border-accent/40">
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-2 text-sm font-semibold">
                      <ShieldCheck className="h-4 w-4 text-accent" /> {FRAMEWORK_LABEL[f] ?? f}
                    </span>
                    <ArrowRight className="h-4 w-4 text-faint transition group-hover:text-accent" />
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-muted">{FRAMEWORK_DESC[f]}</p>
                </Link>
              ))}
            </div>
          </div>
        ))}
      </section>
    </>
  );
}
