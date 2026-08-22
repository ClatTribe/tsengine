import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { ArrowRight, CheckCircle2, MinusCircle, FlaskConical } from "lucide-react";

// THE PROOF PAGE.
//
// The site's only evidence was "Built by ex-Google security engineers" — a credential, not a
// measurement — while the trust bar claimed "Trusted for enterprise deals" with no customer behind
// it. Meanwhile docs/per-asset-scorecard.md holds a real, dated, reproducible benchmark run against
// a corpus we did not write. Publishing that is the honest answer to "why should I believe you".
//
// WHAT MAY BE PUBLISHED IS DECIDED BY THE SCORECARD, NOT BY MARKETING. That document rates its own
// confidence and states outright which figures are unusable: the web per-class numbers are marked
// "not leaderboard-comparable yet" and "must not be quoted" because two identical scans returned
// different case membership. So exactly ONE result clears the bar for a public claim — the SAST
// number, over 2,740 neutral cases, rated High confidence — and this page publishes that one and
// says plainly that the rest is not ready.
//
// The third-place finish is stated, not buried. A vendor that publishes a number where two
// competitors beat it is making a checkable claim; a vendor that publishes only wins is making a
// marketing one. That difference is the entire point of the page.
export const metadata = pageMeta({
  title: "Benchmarks — Corpora We Did Not Write",
  description:
    "Our SAST detection scores 46.5% Youden across all 2,740 OWASP BenchmarkJava cases — third on the published cohort, behind Veracode and Checkmarx. The methodology, the command to reproduce it, and what we have not measured yet.",
  path: "/benchmarks",
});

const COHORT = [
  { name: "Veracode", score: "51", us: false },
  { name: "Checkmarx", score: "47", us: false },
  { name: "TensorShield", score: "46.5", us: true },
  { name: "Fortify", score: "35", us: false },
  { name: "SonarQube", score: "6", us: false },
];

// Everything the scorecard rates below High confidence, stated as not-yet-proof rather than omitted.
const NOT_YET = [
  {
    t: "Web application",
    d: "Measured, but not comparable. Two identical scans returned different case membership, so per-class figures carry unquantified run-to-run variance. The durable finding is a class-level one — script-context XSS went undetected in every run — and that is a capability gap we would rather name than average away.",
  },
  {
    t: "Container, cloud, API",
    d: "Measured and passing, on ground truth too thin to lean on — three CVEs, nineteen seeded CIS violations, one vulnerability class. A perfect score over three cases is worth less than a middling one over 2,740, and reporting them alike is how a benchmark misleads.",
  },
  {
    t: "Domain, IP address",
    d: "Not measured. The fixtures are stubs awaiting a deployed corpus. We would rather show an empty row than a number nobody produced.",
  },
];

export default function Benchmarks() {
  return (
    <>
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <FlaskConical className="h-3.5 w-3.5 text-accent" /> Measured 16 August 2026
          </span>
          <h1 className="mt-6 text-balance text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            Our score on a corpus we didn&apos;t write.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            Every security vendor says best-in-class. Almost none publish a number you can check
            against an answer key they had no hand in. Here is ours, including the two tools that
            beat it.
          </p>
        </div>
      </section>

      {/* The one result that clears the bar for a public claim. */}
      <section className="border-y border-border bg-surface">
        <div className="mx-auto max-w-3xl px-5 py-16">
          <div className="text-xs font-semibold uppercase tracking-wider text-accent">Source-code analysis</div>
          <h2 className="mt-3 text-balance text-3xl font-semibold leading-tight tracking-tight">
            46.5% Youden across all 2,740 OWASP BenchmarkJava cases.
          </h2>
          <p className="mt-4 text-base leading-relaxed text-muted">
            OWASP Benchmark is a deliberately adversarial corpus: every real vulnerability ships
            alongside a safe twin written to look identical to a pattern matcher. Youden is
            sensitivity plus specificity minus one — it credits finding the real bug and ruling out
            the twin, so a tool cannot score by flagging everything.
          </p>

          <div className="mt-8 overflow-x-auto">
            <table className="w-full min-w-[420px] border-collapse text-sm">
              <thead>
                <tr>
                  <th className="border-b border-rule pb-2 text-left text-[11px] font-semibold uppercase tracking-wider text-faint">
                    Published cohort
                  </th>
                  <th className="border-b border-rule pb-2 text-right text-[11px] font-semibold uppercase tracking-wider text-faint">
                    Youden
                  </th>
                </tr>
              </thead>
              <tbody>
                {COHORT.map((c) => (
                  <tr key={c.name} className={c.us ? "bg-accent-soft/50" : undefined}>
                    <td className={`border-b border-border py-2.5 pl-2 ${c.us ? "font-semibold text-accent" : "text-ink"}`}>
                      {c.name}
                    </td>
                    <td
                      className={`border-b border-border py-2.5 pr-2 text-right tabular-nums ${c.us ? "font-semibold text-accent" : "text-muted"}`}
                    >
                      {c.score}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-xs text-faint">
            Competitor figures as published for OWASP Benchmark v1.2. We place third.
          </p>

          {/* The number's own caveat, which is more useful to a buyer than the number. */}
          <div className="mt-8 rounded-xl border border-border bg-bg p-5">
            <div className="text-sm font-semibold text-ink">What the number actually says</div>
            <p className="mt-2 text-sm leading-relaxed text-muted">
              Broken down per category, recall sits at 90–96% while specificity sits at 12–27%. We are
              not missing vulnerabilities — we are failing to rule out the safe twins the corpus ships
              to punish pattern matching. That is a dataflow problem a rule cannot solve in principle,
              which is why the fix is escalating to full taint analysis rather than writing more
              pattern rules.
            </p>
          </div>

          <div className="mt-6 rounded-xl border border-border bg-bg p-5">
            <div className="text-sm font-semibold text-ink">Reproduce it</div>
            <pre className="mt-2 overflow-x-auto rounded-lg bg-surface-2 p-3 text-xs leading-relaxed text-ink">
              <code>tsbench sast --target &lt;BenchmarkJava&gt; --ground-truth expectedresults-1.2.csv</code>
            </pre>
            <p className="mt-2 text-xs leading-relaxed text-faint">
              The corpus and its answer key are OWASP&apos;s, published independently of us.
            </p>
          </div>
        </div>
      </section>

      {/* What we will not claim yet. */}
      <section className="mx-auto max-w-3xl px-5 py-16">
        <div className="text-xs font-semibold uppercase tracking-wider text-accent">Not proof yet</div>
        <h2 className="mt-3 text-balance text-3xl font-semibold leading-tight tracking-tight">
          What we haven&apos;t earned the right to claim.
        </h2>
        <p className="mt-4 text-base leading-relaxed text-muted">
          Everything else we run is either measured on ground truth too thin to generalise from, or
          not measured at all. Those numbers exist internally; they are not on this page because they
          would not survive the scrutiny the one above is inviting.
        </p>

        <div className="mt-8 space-y-3">
          {NOT_YET.map((n) => (
            <div key={n.t} className="flex items-start gap-3 rounded-xl border border-border bg-surface p-5">
              <MinusCircle className="mt-0.5 h-4 w-4 shrink-0 text-faint" />
              <div>
                <div className="text-sm font-semibold text-ink">{n.t}</div>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{n.d}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-8 flex items-start gap-3 rounded-xl border border-pulse/30 bg-pulse-soft p-5">
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" />
          <p className="text-sm leading-relaxed text-ink">
            This is the same rule the product runs on. A finding you see has evidence behind it or it
            does not reach you; a number on this page has a corpus behind it or it does not go up.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-3xl px-5 pb-24">
        <div className="rounded-2xl border border-border bg-surface p-10 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">See it score your own code.</h2>
          <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-muted">
            The scanning engine is free. Connect a repository and you get the same detection this
            benchmark measures, on your codebase.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/signup"
              className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover"
            >
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/sample-report"
              className="inline-flex items-center gap-2 rounded-xl border border-border bg-bg px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong"
            >
              See the report format
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
