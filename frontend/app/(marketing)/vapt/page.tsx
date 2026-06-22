import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import {
  ShieldCheck, ArrowRight, FileCheck2, Bug, Crosshair, Fingerprint, ListChecks,
  Wrench, Radar, CheckCircle2, XCircle, Minus, ScrollText, BadgeCheck, ClipboardCheck,
} from "lucide-react";

export const metadata = pageMeta({
  title: "VAPT report — continuous, evidence-grounded penetration testing | TensorShield",
  description:
    "An always-current VAPT / pentest report: the strongest findings are exploitation-proven with a captured proof-of-concept, every finding grounded in scanner evidence and mapped to CWE, OWASP Top 10 & MITRE ATT&CK, with a recommended fix and a signed attestation. Not a point-in-time PDF that goes stale.",
  path: "/vapt",
});

// What a single finding in the report carries — the "are we at par on quality" answer made concrete.
const FINDING_FIELDS = [
  { icon: Crosshair, t: "Severity + CVSS", d: "Risk-rated and ordered worst-first, with the CVSS base score where the finding carries a CVE." },
  { icon: Bug, t: "CWE + OWASP Top 10", d: "Every finding maps to its CWE and its OWASP Top 10 (2021) category — the taxonomy an enterprise reviewer expects." },
  { icon: Crosshair, t: "MITRE ATT&CK", d: "Techniques attributed per finding, so the report speaks the language of a SOC and a red team." },
  { icon: Fingerprint, t: "Evidence strength — incl. captured PoC", d: "Three tiers labelled inline: exploitation-proven (a reproducible proof-of-concept was captured), tool-confirmed (verified / corroborated), and pattern-match — plus a CISA KEV flag when it's actively exploited in the wild. The strongest tier carries the proof." },
  { icon: Wrench, t: "Recommended fix", d: "An actionable remediation for the finding's class — and where TensorShield has already prepared the fix, it says so." },
  { icon: ScrollText, t: "Tool & rule evidence", d: "The exact scanner and rule that proves it. Nothing is asserted that a tool did not demonstrate." },
];

// Continuous VAPT vs the traditional one-off engagement — the category wedge.
const COMPARE_ROWS: { label: string; cells: string[] }[] = [
  { label: "Coverage — web, API, code, containers, cloud, identity", cells: ["yes", "part"] },
  { label: "Every finding grounded in tool evidence (no hallucinations)", cells: ["yes", "part"] },
  { label: "CWE · OWASP Top 10 · MITRE ATT&CK mapped", cells: ["yes", "part"] },
  { label: "Recommended fix per finding — and the fix shipped on approval", cells: ["yes", "no"] },
  { label: "Signed, tamper-evident, reproducible evidence", cells: ["yes", "no"] },
  { label: "Always current — regenerates as your stack changes", cells: ["yes", "no"] },
  { label: "Turnaround", cells: ["minutes", "2–6 weeks"] },
  { label: "Cost for an SMB", cells: ["$/mo", "$10–30k / test"] },
];

const QUALITY = [
  { icon: Fingerprint, t: "Grounded — never guessed", d: "The engine can't record a vulnerability no tool supports. Every line in the report cites the scanner and rule that proves it (the anti-hallucination guard) — so there are no invented findings inflating the count." },
  { icon: BadgeCheck, t: "Exploitation-proven, not pattern-only", d: "The strongest findings carry a captured, reproducible proof-of-concept (exploitation-proven); others are labelled verified / corroborated vs pattern-match, and actively-exploited issues are flagged against CISA KEV — the accuracy signals a manual pentester earns by hand." },
  { icon: ListChecks, t: "Standards-complete", d: "CWE, OWASP Top 10 (2021) and MITRE ATT&CK on every finding, via the published crosswalks — the same taxonomy a $20k engagement deliverable uses." },
  { icon: Radar, t: "Best-in-class detection underneath", d: "The report is built on 30+ wrapped OSS scanners with recall on par with the standalone tools — depth that matches a human team's toolkit, run continuously." },
];

export default function VAPT() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-3xl px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <FileCheck2 className="h-3.5 w-3.5 text-accent" /> VAPT &amp; penetration-test reporting
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            A pentest report that&apos;s never out of date.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            The customer asks &quot;do you have a recent pentest?&quot; — TensorShield gives you a VAPT report you can
            hand over today, and again next month. Every finding grounded in real scanner evidence, mapped to CWE,
            OWASP Top 10 and MITRE ATT&amp;CK, with a recommended fix and a signed attestation.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/signup"
              className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
            >
              Generate your report <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/demo"
              className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong"
            >
              Talk to sales for a formal engagement
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">Markdown · JSON · signed evidence pack · regenerated on every scan</p>
        </div>
      </section>

      {/* What's in the report */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">What&apos;s in the report</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Every finding, fully worked.</h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            It opens with a prose executive summary and an overall risk rating, then lists each vulnerability worst-first —
            and each one carries everything a security reviewer needs to act.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FINDING_FIELDS.map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Sample finding — show, don't tell */}
      <section className="mx-auto max-w-3xl px-5 py-14">
        <div className="card overflow-hidden p-0 shadow-elevated">
          <div className="flex items-center gap-2 border-b border-border bg-surface px-5 py-3 text-xs font-medium text-muted">
            <ScrollText className="h-3.5 w-3.5 text-accent" /> Excerpt — one finding as it appears in the report
          </div>
          <div className="space-y-2.5 p-5 font-mono text-[13px] leading-relaxed">
            <div className="flex items-center gap-2">
              <span className="rounded-md bg-critical/10 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-critical">Critical</span>
              <span className="font-semibold text-ink">SQL injection in /search</span>
            </div>
            <div className="text-muted"><span className="text-faint">Tool / rule:</span> <span className="text-ink">nuclei · nuclei::sqli-error-based</span></div>
            <div className="text-muted"><span className="text-faint">Location:</span> <span className="text-ink">https://app.acme.io/search?q=</span></div>
            <div className="text-muted"><span className="text-faint">CWE:</span> CWE-89 &nbsp;·&nbsp; <span className="text-faint">OWASP:</span> A03:2021 Injection &nbsp;·&nbsp; <span className="text-faint">MITRE:</span> T1190</div>
            <div className="text-muted"><span className="text-faint">CVSS:</span> 9.8 &nbsp;·&nbsp; <span className="text-faint">Evidence:</span> verified · <span className="font-semibold text-critical">actively exploited (CISA KEV)</span></div>
            <div className="rounded-lg border border-accent/30 bg-accent-soft/30 p-3 font-sans text-[13px] text-ink">
              <span className="font-semibold text-accent">Recommended fix:</span> Use parameterized queries / prepared
              statements; never concatenate user input into SQL. Run the app under a least-privilege database account.
              <span className="text-muted"> (TensorShield has already prepared this fix — it&apos;s awaiting your approval.)</span>
            </div>
          </div>
        </div>
        <p className="mt-3 text-center text-xs text-faint">
          Illustrative excerpt. Real reports contain only grounded findings from your own assets.
        </p>
      </section>

      {/* Quality & accuracy — the explicit question, answered */}
      <section className="bg-surface">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Quality &amp; accuracy</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
              At par with a manual pentest — by construction.
            </h2>
            <p className="mt-3 text-base leading-relaxed text-muted">
              A report is only as good as its findings are true. TensorShield is built so the report can&apos;t claim what
              a tool didn&apos;t prove — the accuracy a good pentester delivers, made structural.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {QUALITY.map(({ icon: Icon, t, d }) => (
              <div key={t} className="card bg-bg p-6">
                <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                  <Icon className="h-4 w-4" />
                </span>
                <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Continuous vs one-off pentest — the wedge */}
      <section className="mx-auto max-w-5xl px-5 py-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Continuous vs one-off</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
            A point-in-time pentest is stale the day after.
          </h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            A traditional engagement is a snapshot — expensive, weeks of lead time, and out of date the moment you ship
            again. TensorShield runs the same assessment continuously and regenerates the report on demand.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] border-separate border-spacing-0 text-sm">
            <thead>
              <tr>
                <th className="w-[48%] p-0" />
                {[
                  { name: "TensorShield", sub: "continuous VAPT", highlight: true },
                  { name: "One-off pentest", sub: "manual engagement", highlight: false },
                ].map((c) => (
                  <th
                    key={c.name}
                    className={`rounded-t-xl px-4 py-3 text-center align-bottom ${c.highlight ? "bg-accent-soft/60 ring-1 ring-accent/30" : ""}`}
                  >
                    <div className={`text-sm font-semibold ${c.highlight ? "text-accent" : "text-ink"}`}>{c.name}</div>
                    <div className="mt-0.5 text-[11px] font-normal text-faint">{c.sub}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {COMPARE_ROWS.map((r, ri) => (
                <tr key={r.label}>
                  <td className="border-t border-border py-3 pr-4 text-sm text-ink">{r.label}</td>
                  {r.cells.map((v, ci) => (
                    <td
                      key={ci}
                      className={`border-t border-border px-4 py-3 text-center ${ci === 0 ? "bg-accent-soft/30" : ""} ${ri === COMPARE_ROWS.length - 1 ? "rounded-b-xl" : ""}`}
                    >
                      <CompareCell v={v} highlight={ci === 0} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-4 text-center text-[11px] text-faint">
          A continuous automated assessment complements, and for many SMB needs replaces, a periodic manual engagement.
          For attestations that require a named human assessor, we can pair you with a partner — talk to sales.
        </p>
      </section>

      {/* How to get it */}
      <section className="bg-surface">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">How to get yours</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">From connect to report in minutes.</h2>
          </div>
          <div className="grid gap-5 md:grid-cols-3">
            {[
              { step: "1", icon: ShieldCheck, t: "Connect your stack", d: "Code, cloud, and identity over one-click OAuth — read-only by default. The agent discovers what to assess." },
              { step: "2", icon: Radar, t: "It runs the assessment", d: "30+ scanners fan out across every asset, findings are verified and grounded, then mapped to CWE / OWASP / MITRE." },
              { step: "3", icon: ClipboardCheck, t: "Download the report", d: "A signed VAPT report in Markdown or JSON — regenerated on every scan, always reflecting your current posture." },
            ].map(({ step, icon: Icon, t, d }) => (
              <div key={t} className="card bg-bg p-6">
                <div className="flex items-center gap-3">
                  <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                    <Icon className="h-5 w-5" />
                  </span>
                  <span className="text-xs font-semibold text-faint">STEP {step}</span>
                </div>
                <h3 className="mt-4 text-lg font-semibold">{t}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA band */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-3xl px-5 py-20 text-center text-white">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Hand your next customer a pentest report.</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">
            Connect your first system and generate a signed, grounded VAPT report for free — then keep it current,
            automatically.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/demo" className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white ring-1 ring-white/20 transition hover:bg-white/15">
              Book a demo
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}

function CompareCell({ v, highlight }: { v: string; highlight: boolean }) {
  if (v === "yes") return <CheckCircle2 className={`mx-auto h-5 w-5 ${highlight ? "text-pulse" : "text-pulse/80"}`} />;
  if (v === "no") return <XCircle className="mx-auto h-5 w-5 text-faint/60" />;
  if (v === "part") return <Minus className="mx-auto h-5 w-5 text-amber-500/70" />;
  return <span className={`text-sm font-semibold ${highlight ? "text-accent" : "text-muted"}`}>{v}</span>;
}
