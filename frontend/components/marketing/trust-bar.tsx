import { ShieldCheck, Boxes, Zap, Building2 } from "lucide-react";

// TrustBar — why you can trust a young security product: who built it, what it runs on, how it's
// built, and who it's for. The first three are verifiable (the team's background, the OSS it wraps,
// its agent-native architecture). The fourth is positioning, not a fabricated logo wall — swap in real
// customer logos here once they're public (do not invent named companies).
const SIGNALS = [
  { icon: ShieldCheck, title: "Built by ex-Google security engineers", sub: "The people who secured hyperscale, now on your side" },
  { icon: Boxes, title: "Runs best-in-class open source", sub: "nuclei · semgrep · trivy · prowler — recall you can trust" },
  { icon: Zap, title: "Agentic-native", sub: "An AI security engineer, not a scanner with a chatbot" },
  { icon: Building2, title: "Trusted for enterprise deals", sub: "Signed, reproducible evidence your buyers accept" },
];

export function TrustBar() {
  return (
    <section className="border-b border-border bg-bg">
      <div className="mx-auto max-w-6xl px-5 py-8">
        <p className="mb-6 text-center text-xs font-medium uppercase tracking-wider text-faint">Why teams trust TensorShield</p>
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {SIGNALS.map(({ icon: Icon, title, sub }) => (
            <div key={title} className="flex items-start gap-3">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <div>
                <div className="text-sm font-semibold leading-snug text-ink">{title}</div>
                <div className="mt-0.5 text-xs leading-snug text-muted">{sub}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
