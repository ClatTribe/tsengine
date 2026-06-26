import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";

import { ArrowRight, ShieldCheck } from "lucide-react";
import { FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_DESC, FRAMEWORK_CATEGORY } from "@/lib/frameworks";

export const metadata = pageMeta({
  title: "Compliance Frameworks — SOC 2, ISO 27001, HIPAA, CMMC, EU AI Act & more | TensorShield",
  description:
    "TensorShield automates 22 compliance frameworks — SOC 2, ISO 27001/27701/27018/22301, PCI-DSS, HIPAA, GLBA, SOX, CIS, NIST CSF/800-53/800-171, FedRAMP, CMMC, GDPR, CCPA, PIPEDA, India DPDP, ISO 42001, NIST AI RMF, and the EU AI Act — plus bring-your-own-framework, with continuous monitoring and signed evidence.",
  path: "/frameworks",
});

const CATEGORY_ORDER = ["Security & trust", "Sector & payments", "Privacy", "Government", "AI governance"];

export default function FrameworksIndex() {
  const groups = CATEGORY_ORDER.map((cat) => ({
    cat,
    items: FRAMEWORKS.filter((f) => (FRAMEWORK_CATEGORY[f] ?? "Security & trust") === cat),
  })).filter((g) => g.items.length > 0);

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
