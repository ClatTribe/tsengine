import { ShieldCheck, Boxes, Zap, Building2 } from "lucide-react";
import { Reveal } from "@/components/marketing/reveal";

// TrustBar — why you can trust a young security product: who built it, what it runs on, how it's
// built, and who it's for. The first three are verifiable (the team's background, the OSS it wraps,
// its agent-native architecture). The fourth is positioning, not a fabricated logo wall — swap in real
// customer logos here once they're public (do not invent named companies).
const SIGNALS = [
  { icon: ShieldCheck, title: "Built by ex-Google security engineers", sub: "The people who secured hyperscale, now on your side" },
  { icon: Boxes, title: "Runs best-in-class open source", sub: "30+ wrapped scanners — recall on par with the standalone tools" },
  { icon: Zap, title: "Agentic-native", sub: "An AI security engineer, not a scanner with a chatbot" },
  { icon: Building2, title: "Trusted for enterprise deals", sub: "Signed, reproducible evidence your buyers accept" },
];

// The real OSS tools the engine wraps (CLAUDE.md §13) — scrolled as a live marquee, the "stands on
// proven shoulders" trust signal. All shipped; nothing invented.
const OSS = [
  "nuclei", "semgrep", "trivy", "prowler", "gitleaks", "grype", "trufflehog",
  "checkov", "kics", "dockle", "sqlmap", "subfinder", "nmap", "govulncheck", "dalfox", "mobsfscan",
];

export function TrustBar() {
  return (
    <section className="border-b border-border bg-bg">
      <div className="mx-auto max-w-6xl px-5 py-14">
        <Reveal className="text-center">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">Why teams trust TensorShield</h2>
          <p className="mx-auto mt-2.5 max-w-xl text-sm leading-relaxed text-muted">
            A young product — but not an unproven one. Here&apos;s what it&apos;s built on.
          </p>
        </Reveal>

        {/* live marquee of the wrapped open-source scanners */}
        <Reveal
          delay={60}
          className="relative mt-8 overflow-hidden [mask-image:linear-gradient(to_right,transparent,black_8%,black_92%,transparent)]"
        >
          <div className="flex w-max gap-2.5 animate-marquee">
            {[...OSS, ...OSS].map((name, i) => (
              <span
                key={`${name}-${i}`}
                className="mono shrink-0 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted shadow-sm"
              >
                {name}
              </span>
            ))}
          </div>
        </Reveal>

        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {SIGNALS.map(({ icon: Icon, title, sub }, i) => (
            <Reveal key={title} delay={90 + i * 70}>
              <div className="card lift h-full p-5">
                <span className="grid h-11 w-11 place-items-center rounded-xl bg-accent-soft text-accent ring-1 ring-accent/10">
                  <Icon className="h-5 w-5" />
                </span>
                <div className="mt-4 text-sm font-semibold leading-snug text-ink">{title}</div>
                <div className="mt-1 text-xs leading-snug text-muted">{sub}</div>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
