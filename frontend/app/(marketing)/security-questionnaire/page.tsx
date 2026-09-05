import Link from "next/link";
import { ArrowRight, CheckCircle2, UserCheck, Radar, FileText } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";

// The trigger-intent page: "how do I answer a security questionnaire". The product's answer is the
// 52-question two-tier questionnaire (§8) — 35 OBSERVED questions a scanner answers from evidence,
// 17 ATTESTED that only a named human can answer — and the honesty design IS the pitch: a "Yes"
// exists only where the evidence source is connected, a human's answer is rendered as theirs with a
// date, and nothing is inferred across the line. The counts and domains below are transcribed from
// internal/grc/questionnaire_corpus.go; change them there and here together.
export const metadata = pageMeta({
  title: "How to Answer a Security Questionnaire",
  description:
    "Answer CAIQ/SIG-style security questionnaires with evidence, not adjectives: 36 questions a scan answers, 16 a named human attests. Free to try.",
  path: "/security-questionnaire",
});

const OBSERVED_DOMAINS = [
  ["Access control", 6],
  ["Vulnerability management", 6],
  ["Infrastructure", 4],
  ["Cryptography", 3],
  ["Endpoint security", 3],
  ["External exposure", 2],
  ["Incident response", 2],
  ["Logging & monitoring", 2],
  ["Secure development", 2],
  ["Vendor / third-party", 2],
  ["Data protection", 1],
  ["Email security", 1],
  ["SaaS security", 1],
  // Personnel arrived here when the training programme landed: "do employees receive security
  // awareness training annually" stopped being something only a person could answer.
  ["Personnel", 1],
] as const;

const ATTESTED_DOMAINS = [
  ["Data protection", 4],
  ["Business continuity", 3],
  ["Governance", 3],
  ["Personnel", 2],
  ["Change management", 1],
  ["Incident response", 1],
  ["Physical security", 1],
  ["Vendor / third-party", 1],
] as const;

const ANSWERS = [
  { a: "Yes", d: "A scanner looked at the connected system and found the control in place. Only an observed question can say this, and only when its evidence source is connected." },
  { a: "In Progress", d: "A real finding is open against a control this question maps to. The answer changes when the finding closes — not when someone edits the document." },
  { a: "No", d: "The check ran and the control is absent. A questionnaire that cannot say no is a form with one answer, and a buyer knows it." },
  { a: "Not assessed", d: "Nothing that could answer this is connected yet. Fixed by connecting a system, not by typing." },
  { a: "Needs your answer", d: "No scan can see this — background checks, DR rehearsals, insurance. A named person answers, and the document says who and when." },
];

export default function SecurityQuestionnairePage() {
  return (
    <>
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-12 pt-16 text-center sm:pt-20">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-accent">
            <FileText className="h-3.5 w-3.5" /> Security questionnaires
          </span>
          <h1 className="mx-auto mt-3 max-w-2xl text-balance text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
            Answer the questionnaire with evidence, not adjectives.
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            A customer&apos;s security team sends 200 questions and a deadline. Most answers get written from memory
            and hope. Ours are answered by the scan where a scan can see, by a named person where it can&apos;t, and
            the document never blurs which is which.
          </p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Connect a system, get answers <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/scan" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-2.5 text-sm font-semibold text-ink transition hover:border-accent/40">
              <Radar className="h-4 w-4 text-accent" /> Start with the free domain scan
            </Link>
          </div>
        </div>
      </section>

      {/* The two tiers — the design is the pitch. */}
      <section className="border-y border-border bg-surface">
        <div className="mx-auto max-w-4xl px-5 py-16">
          <div className="text-xs font-semibold uppercase tracking-wider text-accent">Two kinds of answer, never mixed</div>
          <h2 className="mt-3 text-balance text-3xl font-semibold leading-tight tracking-tight">
            36 questions a scan answers. 16 only a person can.
          </h2>
          <p className="mt-4 max-w-2xl text-base leading-relaxed text-muted">
            Every other tool renders a typed &quot;Yes&quot; identically to an observed one. We keep them apart
            because a buyer&apos;s reviewer will ask &quot;how do you know?&quot; on the first row they doubt, and the
            honest answer is different for each.
          </p>
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            <div className="rounded-2xl border border-pulse/30 bg-pulse/5 p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-ink">
                <CheckCircle2 className="h-4 w-4 text-pulse" /> Observed — answered by the scan
              </div>
              <p className="mt-2 text-sm leading-relaxed text-muted">
                A question earns this slot only when a detector in the product actually produces the signal. A
                &quot;Yes&quot; requires the evidence source to be connected; nothing connected reads &quot;Not
                assessed&quot;, never &quot;Yes&quot;. A typed answer is refused here — it would replace an
                observation with an opinion.
              </p>
              <ul className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1 text-sm text-muted">
                {OBSERVED_DOMAINS.map(([name, n]) => (
                  <li key={name} className="flex justify-between gap-2"><span>{name}</span><span className="tabular-nums text-faint">{n}</span></li>
                ))}
              </ul>
            </div>
            <div className="rounded-2xl border border-border bg-bg p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-ink">
                <UserCheck className="h-4 w-4 text-accent" /> Attested — answered by a named human
              </div>
              <p className="mt-2 text-sm leading-relaxed text-muted">
                Background checks, DR rehearsals, insurance, policy sign-off: no scan can see these, and a tool
                that pretends otherwise is lying on your behalf. A named person answers, both Yes and No are
                real options, and the row renders &quot;stated by &lt;name&gt; on &lt;date&gt;&quot;. A finding is never
                allowed to infer one of these.
              </p>
              <ul className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1 text-sm text-muted">
                {ATTESTED_DOMAINS.map(([name, n]) => (
                  <li key={name} className="flex justify-between gap-2"><span>{name}</span><span className="tabular-nums text-faint">{n}</span></li>
                ))}
              </ul>
            </div>
          </div>
          <p className="mt-6 text-xs leading-relaxed text-faint">
            Why 52 and not the 261 in CAIQ v4: most of those ask about things no scanner can see, so importing them
            wholesale turns ten unanswered rows into two hundred and thirty. The proportion answered does not
            improve; the reader just wades through more admissions. We map to CAIQ / SIG-Lite control ids so a
            reviewer can cross-reference, and we grow the observed set only as fast as the detectors do.
          </p>
        </div>
      </section>

      {/* What each answer means. */}
      <section className="mx-auto max-w-3xl px-5 py-16">
        <div className="text-xs font-semibold uppercase tracking-wider text-accent">Five answers, each with a meaning</div>
        <h2 className="mt-3 text-balance text-3xl font-semibold leading-tight tracking-tight">
          No single score — a percentage would rise as you connected less and asserted more.
        </h2>
        <div className="mt-8 space-y-3">
          {ANSWERS.map((x) => (
            <div key={x.a} className="flex items-start gap-4 rounded-xl border border-border bg-surface p-5">
              <div className="w-36 shrink-0 text-sm font-semibold text-ink">{x.a}</div>
              <p className="text-sm leading-relaxed text-muted">{x.d}</p>
            </div>
          ))}
        </div>
        <p className="mt-6 text-sm leading-relaxed text-muted">
          The rendered document carries two separate notes above the table — what needs a system connected, and
          what needs a person to sit down — because merged, the reader is told to fix the wrong thing. The same
          answers feed the buyer-facing <span className="font-medium text-ink">Trust Center</span> (your own page at /trust/&lt;workspace&gt; once you sign up),
          so the next questionnaire is a link, not a fortnight.
        </p>
      </section>

      <section className="mx-auto max-w-3xl px-5 pb-24">
        <div className="rounded-2xl border border-border bg-surface p-10 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">See which of the 35 you can already answer.</h2>
          <p className="mx-auto mt-3 max-w-lg text-sm leading-relaxed text-muted">
            Connect one system on the free tier and the observed rows fill in from real evidence. Prefer to start
            outside-in? The free domain scan covers the email-auth and web-posture rows without an account.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Create a free workspace <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/resources" className="text-sm font-medium text-accent hover:underline">
              Or download the questionnaire template →
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
