import Link from "next/link";
import { ShieldCheck, Boxes, Zap, Building2 } from "lucide-react";
import { Reveal } from "@/components/marketing/reveal";

// TrustBar — why you can trust a young security product: who built it, what it runs on, how it's
// built, and what it scores. All four are now verifiable: the team's background, the OSS it wraps,
// its agent-native architecture, and a benchmark run against a corpus we did not write.
//
// The fourth slot used to read "Trusted for enterprise deals" and carried a note to swap in real
// customer logos once they were public. A measured, checkable number is a better tenant for that
// slot than positioning was — and it keeps the note's rule intact: nothing invented, no named
// companies we cannot show. Swap in real logos here when there are some; do not invent them.
const SIGNALS = [
  { icon: ShieldCheck, title: "Built by ex-Google security engineers", sub: "The people who secured hyperscale, now on your side" },
  { icon: Boxes, title: "Runs best-in-class open source", sub: "30+ wrapped scanners — recall on par with the standalone tools" },
  { icon: Zap, title: "Agentic-native", sub: "An AI security engineer, not a scanner with a chatbot" },
  // Was "Trusted for enterprise deals · Signed, reproducible evidence your buyers accept" — a
  // social-proof claim with no customer behind it, on a site with no logos, no quotes and no named
  // references. It asked the reader to take trust on assertion, which is the one thing the rest of
  // this product refuses to do.
  //
  // Replaced with the strongest claim we can actually back: a benchmark run against a corpus we did
  // not write, third on the published cohort. It is a weaker-sounding sentence and a much stronger
  // piece of evidence, and unlike the one it replaces a reader can go and check it.
  { icon: Building2, title: "46.5% on OWASP Benchmark", sub: "Third on the published cohort, over 2,740 neutral cases — see the workings", href: "/benchmarks" },
];

// The real OSS tools the engine wraps (CLAUDE.md §13) — scrolled as a live marquee, the "stands on
// proven shoulders" trust signal. All shipped; nothing invented.
const OSS = [
  "nuclei", "semgrep", "trivy", "prowler", "gitleaks", "grype", "trufflehog",
  "checkov", "kics", "dockle", "sqlmap", "subfinder", "nmap", "govulncheck", "dalfox", "mobsfscan",
];

export function TrustBar() {
  return (
    <div>
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
          {SIGNALS.map(({ icon: Icon, title, sub, href }: { icon: typeof ShieldCheck; title: string; sub: string; href?: string }, i) => (
            <Reveal key={title} delay={90 + i * 70}>
              {/* A claim that invites checking has to be reachable, so the benchmark card links to
                  the workings. The others are statements of fact with nowhere to go. */}
              {href ? (
                <Link href={href} className="card lift group block h-full p-5 transition hover:border-accent/40">
                  <span className="grid h-11 w-11 place-items-center rounded-xl bg-accent-soft text-accent ring-1 ring-accent/10">
                    <Icon className="h-5 w-5" />
                  </span>
                  <div className="mt-4 text-sm font-semibold leading-snug text-ink group-hover:text-accent">{title}</div>
                  <div className="mt-1 text-xs leading-snug text-muted">{sub}</div>
                </Link>
              ) : (
                <div className="card lift h-full p-5">
                  <span className="grid h-11 w-11 place-items-center rounded-xl bg-accent-soft text-accent ring-1 ring-accent/10">
                    <Icon className="h-5 w-5" />
                  </span>
                  <div className="mt-4 text-sm font-semibold leading-snug text-ink">{title}</div>
                  <div className="mt-1 text-xs leading-snug text-muted">{sub}</div>
                </div>
              )}
            </Reveal>
          ))}
        </div>
      </div>
    </div>
  );
}
