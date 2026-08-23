import Link from "next/link";
import {
  ShieldCheck, Sparkles, ArrowRight, Plug, ScanLine, CheckCircle2, FileCheck2,
  Lock, Cloud, KeyRound, Star, Wrench, Mail, ClipboardCheck,
  Activity, ChevronDown, GitBranch, XCircle, Minus, Wallet, Crosshair,
} from "lucide-react";
import { ProviderIcon } from "@/components/brand/provider-icon";
import { SecurityReviewHero } from "@/components/marketing/security-review-hero";
import { VerificationPromise } from "@/components/marketing/verification-promise";
import { Reveal } from "@/components/marketing/reveal";
import { TrustBar } from "@/components/marketing/trust-bar";
import { Prioritize } from "@/components/marketing/prioritize";
import { SCENARIOS, SURFACES, ALTERNATIVES } from "@/lib/solutions";
import { FRAMEWORK_COUNT } from "@/lib/frameworks";
import { pageMeta } from "@/lib/seo";

const HOME_TITLE = "Clear the security review blocking your deal";
const HOME_DESCRIPTION =
  "An AI security engineer finds what an attacker could reach across code, cloud, identity and SaaS and writes the fix. An AI pentester proves it by breaking in.";

// The social card must say what the H1 says. Both now lead with the visitor's SITUATION — a deal
// stuck behind a customer's security review — rather than with the two agents, which are the how.
// A shared link that promises a different thing from the page it opens is a positioning leak.
const HOME_SOCIAL =
  "A customer's security review is holding up the deal. An AI security engineer finds what an attacker could actually reach and writes the fix; an AI pentester proves it by breaking in. You approve every change, and you get the signed report their security team is asking for.";

// Through pageMeta() like every other route. It used to hand-roll `openGraph`, and because a
// page-level openGraph object REPLACES the parent's file-convention image rather than merging
// with it, declaring one without `images` published no share card at all — on the single
// most-linked URL on the site. The fix is not "remember the images key", it is that no route
// hand-rolls this. ADR 0023 decision 2.
export const metadata = pageMeta({
  title: HOME_TITLE,
  description: HOME_DESCRIPTION,
  path: "/",
  socialTitle: "Clear the security review that's holding up your deal.",
  socialDescription: HOME_SOCIAL,
});

export default function Landing() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        {/* animated aurora backdrop — modern depth, subtle motion */}
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute -top-24 left-[20%] h-[26rem] w-[26rem] -translate-x-1/2 rounded-full bg-accent/20 blur-[110px] animate-aurora" />
          <div className="absolute -top-16 right-[16%] h-[22rem] w-[22rem] translate-x-1/2 rounded-full bg-pulse/15 blur-[110px] animate-aurora [animation-delay:-7s]" />
          <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(16,24,40,0.025)_1px,transparent_1px),linear-gradient(to_bottom,rgba(16,24,40,0.025)_1px,transparent_1px)] bg-[size:44px_44px] [mask-image:radial-gradient(ellipse_at_top,black,transparent_72%)]" />
        </div>
        <div className="relative mx-auto max-w-6xl px-5 pb-16 pt-16 lg:pt-24">
          <div className="grid items-center gap-12 lg:grid-cols-2">
            {/* copy — DELIBERATELY SHORT.
                This column used to carry seven things and ~130 words: a badge, the headline, two
                paragraphs, two buttons, a fine-print framework list and a second link. A hero has one
                job — say what this is and give one way in — and every extra element competes with the
                picture that explains it faster than prose can. What was cut and where it went:
                  · the qualifier paragraph  → already said by the badge, so it was said twice
                  · "See how the attack path works" → the attack path is rendered right beside it
                  · the framework fine print → StackPipeline and the trust bar below both carry it
                What replaced 80 words of prose is two scannable lines, because the headline promises
                two agents and a reader should SEE the two rather than parse a sentence about them. */}
            <div className="text-center lg:text-left">
              <Link
                href="/product"
                className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface/80 px-3 py-1 text-xs font-medium text-muted shadow-sm backdrop-blur transition hover:border-accent/40"
              >
                <Sparkles className="h-3.5 w-3.5 text-accent" /> For Series A and B teams
              </Link>

              {/* The headline names the visitor's SITUATION, not our machinery.
                  It used to read "Your AI security engineer. And your AI pentester." — accurate,
                  differentiated, and a description of what we built rather than of what the reader
                  came here with. The buying trigger is all over this site (the /startups page, all
                  three blog posts, both lead magnets, and the first option in our own "what brought
                  you here?" router): a deal is stuck behind a customer's security review. That was
                  arriving at 73% scroll depth. It leads now; the two agents follow one line down as
                  the HOW, which is what they are. */}
              <h1 className="mx-auto mt-6 max-w-xl text-balance text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl lg:mx-0 lg:text-[3.4rem]">
                Clear the security review{" "}
                <span className="text-accent">that&apos;s holding up your deal.</span>
              </h1>
              <p className="mx-auto mt-5 max-w-md text-lg leading-relaxed text-muted lg:mx-0">
                Two AI teammates do the work a security hire would — and hand you the signed report
                your customer is asking for.
              </p>

              {/* The headline's promise, made visible. Two rows, one job each — scannable in about a
                  second, where the paragraph they replace took a paragraph's worth of attention. */}
              <div className="mx-auto mt-6 max-w-md space-y-2.5 lg:mx-0">
                <AgentLine
                  Icon={ShieldCheck}
                  name="AI security engineer"
                  job="finds what an attacker could actually reach — and writes the fix"
                />
                <AgentLine
                  Icon={Crosshair}
                  name="AI pentester"
                  job="proves it by breaking in, then re-tests your fix"
                />
              </div>

              <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row lg:justify-start">
                <Link
                  href="/signup"
                  className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
                >
                  Start free <ArrowRight className="h-4 w-4" />
                </Link>
                <Link href="/scan" className="text-sm font-medium text-accent hover:underline">
                  or check your domain — free, no signup
                </Link>
              </div>
              <p className="mt-4 text-xs text-faint">No credit card · You approve every change</p>
            </div>

            {/* The outcome, not the mechanism. The cloud-IAM attack-path graph that used to sit here
                is the engineer's picture — it asks a founder to parse a node graph before they feel
                anything. It now lives on /ai-security-engineer, where the reader has opted into the
                mechanics; the hero shows the review clearing and the report they can send back. */}
            <div>
              <SecurityReviewHero />
            </div>
          </div>

        </div>
      </section>


      {/* ── 2 · WHERE DO YOU FIT ────────────────────────────────────────────────────────────────
          Moved up from position 11 (y≈5,746 of 7,900 — 73% scroll depth). Visitors arrive at this
          product from very different places, and the highest-intent one ("a deal is blocked on a
          security questionnaire") was the first item in a list almost nobody scrolled to. Asking
          early costs one screen and routes each reader to a page written for their actual question,
          instead of making all of them read the same twelve bands hoping to recognise themselves. */}
      <SolutionsRouter />

      {/* ── 3 · WHAT YOU GET ────────────────────────────────────────────────────────────────────
          Was TWO adjacent sections that both carried the eyebrow "WHAT YOU GET": the stack pipeline
          and the two-agent cards. One band now — the pipeline shows what plugs in and what comes
          out, the cards say what the agents actually do. */}
      <section className="border-y border-border bg-surface">
        <div className="mx-auto max-w-6xl px-5 py-16">
          <StackPipeline />
          <div className="mt-14">
            <TwoAgents />
          </div>
        </div>
      </section>

      {/* ── 4 · WHY YOU CAN TRUST IT ────────────────────────────────────────────────────────────
          The verification promise and the signed-evidence block were separated by five sections,
          and they answer the same question — can I believe what this thing tells me. Verification
          covers how a finding is admitted; evidence covers what an auditor can re-run afterwards.
          Together they are one argument. */}
      <section className="border-y border-border bg-bg">
        <VerificationPromise />
        <div className="border-t border-border">

        <div className="mx-auto grid max-w-6xl items-center gap-10 px-5 py-20 lg:grid-cols-2">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Built on trust</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
              Evidence you can prove — not screenshots you hope hold up.
            </h2>
            <p className="mt-4 text-base leading-relaxed text-muted">
              Every finding cites the tool that backs it, and every compliance artifact is signed and pinned to the exact
              state it was assessed against. An auditor can re-run the proof. Your customers can trust the badge.
            </p>
            <ul className="mt-6 space-y-3">
              {[
                "Evidence your auditor can verify wasn’t edited after the fact",
                "Every issue links to the tool that proved it — the AI never asserts what nothing proved",
                "A signed decision ledger for every automated and human action",
              ].map((x) => (
                <li key={x} className="flex items-start gap-2.5 text-sm text-ink">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {x}
                </li>
              ))}
            </ul>
            <Link href="/security" className="mt-7 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
              How we keep you safe <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          <ConnectorsVisual />
        </div>
              </div>
      </section>

      {/* ── 5 · FROM NOISE TO FIXED ─────────────────────────────────────────────────────────────
          The funnel ("we cut 1,200 signals to 6") and the differentiator ("and then we fix them")
          were two sections making one continuous argument, with a stat strip wedged between them.
          Read together they are the product's whole value in one band: less noise, then a shipped
          fix, then proof it is closed. */}
      <section className="border-y border-border bg-surface">
        <Prioritize />
        <div className="border-t border-border">

        <div className="mx-auto max-w-5xl px-5 py-16">
          <Reveal className="mb-10 grid gap-x-10 gap-y-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] md:items-end">
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider text-accent">The difference</span>
              <h2 className="mt-3 text-balance text-3xl font-semibold leading-tight tracking-tight">
                Most tools stop at the finding. TensorShield ships the fix.
              </h2>
            </div>
            <p className="text-base leading-relaxed text-muted md:pb-1">
              A dashboard full of risks is still your problem to solve. TensorShield prepares the actual remediation —
              and applies it the moment you approve.
            </p>
          </Reveal>
          <Reveal delay={90} className="grid gap-4 sm:grid-cols-2">
            <div className="card p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-muted">
                <XCircle className="h-4 w-4 text-faint" /> Advise-only tools
              </div>
              <ul className="mt-4 space-y-2.5 text-sm text-muted">
                {["Hand you a list of risks", "“Remediation guidance” you implement yourself", "You still need an engineer to act", "“Fixed” means the scanner stopped flagging it", "Evidence you assemble by hand"].map((x) => (
                  <li key={x} className="flex items-start gap-2.5">
                    <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-faint" /> {x}
                  </li>
                ))}
              </ul>
            </div>
            <div className="card border-accent/40 bg-accent-soft/30 p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-accent">
                <Wrench className="h-4 w-4" /> TensorShield
              </div>
              <ul className="mt-4 space-y-2.5 text-sm text-ink">
                {[
                  "Opens the pull request with the fix",
                  "Applies the cloud / identity change on approval",
                  // The strongest claim on this page, and the one it would be easiest to overstate.
                  // Re-testing after a fix runs for everyone. Re-running the actual EXPLOIT needs the
                  // AI Pentester and an engagement you have authorised for active testing — so the
                  // condition is stated here rather than discovered later. The neighbouring column
                  // mocks "fixed means the scanner stopped flagging it"; claiming more than we do by
                  // default would put us in that column.
                  "Re-tests every fix — and on an authorised engagement, re-runs the exploit to prove it is dead",
                  "Auto-handles the low-risk work; gates the rest",
                  "Signs the evidence pack automatically",
                ].map((x) => (
                  <li key={x} className="flex items-start gap-2.5">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {x}
                  </li>
                ))}
              </ul>
            </div>
          </Reveal>

          {/* From alert to fixed — USP #2 made tangible: the concrete remediation path, animated */}
          <Reveal delay={150} className="mt-8 rounded-2xl border border-border bg-bg p-4 sm:p-5">
            <div className="mb-4 text-center text-[11px] font-semibold uppercase tracking-wider text-faint">
              From alert to proven closed — automatically, with you approving what matters
            </div>
            <div className="flex min-w-max items-stretch gap-1.5 overflow-x-auto sm:min-w-0 sm:justify-center [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
              {[
                { icon: ScanLine, t: "Detected", d: "ranked, deduped" },
                { icon: Wrench, t: "Fix prepared", d: "PR · config · runbook" },
                { icon: CheckCircle2, t: "You approve", d: "1 tap; routine fixes skip you" },
                { icon: GitBranch, t: "Applied", d: "via your connector" },
                { icon: ShieldCheck, t: "Proven closed", d: "tested again, not assumed" },
              ].map(({ icon: Icon, t, d }, i, arr) => (
                <div key={t} className="flex items-stretch gap-1.5">
                  <div className="w-[8.2rem] shrink-0 rounded-xl border border-border bg-surface p-3 text-center shadow-card">
                    <span className="mx-auto grid h-8 w-8 place-items-center rounded-lg bg-accent-soft text-accent">
                      <Icon className="h-4 w-4" />
                    </span>
                    <div className="mt-2 text-xs font-semibold text-ink">{t}</div>
                    <div className="mt-0.5 text-[11px] leading-snug text-muted">{d}</div>
                  </div>
                  {i < arr.length - 1 && (
                    <div className="flex w-6 shrink-0 items-center self-center">
                      <div className="relative h-px w-full bg-gradient-to-r from-border via-accent/40 to-border">
                        <span
                          className="absolute top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent shadow-[0_0_8px_rgba(79,70,229,0.6)] animate-flow-x"
                          style={{ animationDelay: `${i * 0.45}s` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Reveal>
        </div>
              </div>
      </section>

      {/* ── 6 · WHO IS BEHIND IT ────────────────────────────────────────────────────────────────
          The trust bar and the stat strip both answered "is this real?" — one with provenance, one
          with numbers — from opposite ends of the page. Merged, with the counts corrected: the
          strip still read 22 frameworks against an engine that ships 25. */}
      <section className="border-y border-border bg-bg">
        <TrustBar />
        <div className="border-t border-border">
          <Reveal className="mx-auto grid max-w-5xl grid-cols-2 gap-6 px-5 py-10 text-center sm:grid-cols-4">
            {[
              [String(FRAMEWORK_COUNT), "compliance frameworks"],
              ["30+", "open-source scanners"],
              ["24/7", "continuous monitoring"],
              ["1-tap", "approval, fully signed"],
            ].map(([n, l]) => (
              <div key={l}>
                <div className="text-3xl font-semibold tracking-tight text-ink">{n}</div>
                <div className="mt-1 text-xs text-muted">{l}</div>
              </div>
            ))}
          </Reveal>
        </div>
      </section>

      {/* ── 7 · START ───────────────────────────────────────────────────────────────────────────
          The three setup steps and the closing CTA were separated by two sections. They are one
          thought — here is how you begin, here is the button — so they close the page together.

          CUT ENTIRELY on the way here: <ArchStack />, which carried a second "HOW IT WORKS" eyebrow
          (the first is below) and re-explained the two agents plus the free engine plus the human
          who signs. All three already land: the agents in band 3, the free engine in that band's
          footer line, the human in each agent's boundary line. Saying it a third time did not make
          it more persuasive, only further from the CTA. */}
      <section>
      <Section eyebrow="How it works" title="Set up once. It runs itself." sub="Connect a system and the agent takes it from there — you stay in control of anything risky.">
        <div className="grid gap-5 md:grid-cols-3">
          {[
            { icon: Plug, step: "1", t: "Connect", d: "GitHub, AWS, Google Workspace, Okta — one click of OAuth. The agent discovers what to watch." },
            { icon: ScanLine, step: "2", t: "The agent works", d: "It scans continuously, triages real risk from noise, and prepares the fix — patches, configs, tickets." },
            { icon: CheckCircle2, step: "3", t: "You approve", d: "Anything consequential waits for one tap of your approval. Everything is signed and auditable." },
          ].map(({ icon: Icon, step, t, d }) => (
            <div key={t} className="card p-6">
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
      </Section>


        {/* the button, in the same band as the steps that lead to it */}
        <div className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-3xl px-5 py-20 text-center text-white">
          {/* Was "Give your startup a security team today." The hero badge says Series A and B; a
              closing line that calls the same reader a startup tells them we haven't decided who
              this is for. Same offer, consistent audience. */}
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Get your security team running this week.</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">
            Connect your first system in minutes. See your posture, your compliance gaps, and your first fixes — for free.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/pricing" className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white ring-1 ring-white/20 transition hover:bg-white/15">
              See pricing
            </Link>
          </div>
        </div>
        </div>
      </section>
    </>
  );
}

// SolutionsRouter — the homepage's hand-off.
//
// A landing page can only make one argument well. Ours is the wedge (hero) plus the two things that
// actually differentiate us (we prioritise; we ship the fix). Everything after that is a DIFFERENT
// visitor's question, and the honest move is to route rather than to keep talking.
//
// The three lanes mirror /solutions exactly — someone arrives with a situation, a surface, or an
// incumbent they're comparing against. We show a few of each and link to the full hub, so the page
// stays short while every one of the 39 marketing pages stays one or two clicks away.
// TwoAgents is the answer to "what am I actually buying, and is it for me?".
//
// The homepage previously made a visitor scroll through the trust bar, the noise funnel and the
// differentiator band before naming the two agents. That is the wrong order for a founder who has
// thirty seconds and one question. Each card leads with the job title, states the work in the
// customer's words, and ends with the boundary — what the agent will not do on its own — because for
// this buyer "it opens a PR" and "it merges to main" are very different products.
function TwoAgents() {
  const agents = [
    {
      Icon: ShieldCheck,
      kicker: "Defends",
      title: "AI Security Engineer",
      lede: "Finds what an attacker could actually reach, and writes the fix.",
      does: [
        "Cuts a thousand scanner alerts down to the handful that matter",
        "Connects a problem in your code to what it unlocks in your cloud — one issue, not three tickets",
        "Explains each issue in plain English, then opens the PR or config change",
      ],
      boundary: "Never applies anything on its own — you approve every change.",
      href: "/ai-security-engineer",
      cta: "How the engineer works",
    },
    {
      Icon: Wrench,
      kicker: "Attacks",
      title: "AI Pentester",
      lede: "Proves it by breaking in — not a scanner's guess.",
      does: [
        "Actually breaks in to prove it is real — safely, inside limits you set",
        "Shows you the exact request that worked, so nothing is taken on trust",
        "Re-tests after your fix to show the hole is really closed",
      ],
      boundary: "Only runs against targets you scope and sign off on.",
      href: "/ai-pentest",
      cta: "How the pentester works",
    },
  ];

  return (
    <div>
      <div>
        <Reveal className="mb-10 grid gap-x-10 gap-y-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] md:items-end">
          {/* Was also "What you get" — the same eyebrow the stack pipeline directly above already
              uses for its outcomes column. Harmless when the two sat in different sections; inside
              one band it reads as the page repeating itself. The pipeline keeps the outcome
              framing, these cards name the agents. */}
          <div>
            <div className="text-xs font-medium uppercase tracking-wider text-faint">The two agents</div>
            <h2 className="mt-2 text-balance text-3xl font-semibold tracking-tight sm:text-4xl">Two AI teammates, one human in charge</h2>
          </div>
          <p className="text-base leading-relaxed text-muted md:pb-1">
            Not a dashboard you have to staff. Two agents that do the work a security hire would, on the
            scanning engine underneath — with you signing off on anything that matters.
          </p>
        </Reveal>

        <Reveal delay={80} className="grid gap-5 md:grid-cols-2">
          {agents.map(({ Icon, kicker, title, lede, does, boundary, href, cta }) => (
            <div key={title} className="card flex flex-col p-6">
              <div className="flex items-center gap-3">
                <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent">
                  <Icon className="h-5 w-5" />
                </span>
                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-accent">{kicker}</div>
                  <div className="text-lg font-semibold text-ink">{title}</div>
                </div>
              </div>
              <p className="mt-4 text-sm font-medium text-ink">{lede}</p>
              <ul className="mt-3 space-y-2">
                {does.map((d) => (
                  <li key={d} className="flex items-start gap-2.5 text-sm leading-relaxed text-muted">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {d}
                  </li>
                ))}
              </ul>
              {/* The boundary matters as much as the capability for this buyer. */}
              <p className="mt-4 flex items-start gap-2 rounded-lg border border-border bg-bg px-3 py-2 text-xs leading-relaxed text-muted">
                <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-faint" /> {boundary}
              </p>
              <Link
                href={href}
                className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-accent transition hover:underline"
              >
                {cta} <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          ))}
        </Reveal>

        <Reveal delay={140} className="mt-6 text-center text-sm text-muted">
          Prefer to start without AI?{" "}
          <Link href="/pricing" className="font-medium text-accent hover:underline">
            The scanning engine is free
          </Link>{" "}
          — turn either agent on when you are ready.
        </Reveal>
      </div>
    </div>
  );
}

function SolutionsRouter() {
  const lanes = [
    {
      href: "/solutions#scenarios",
      eyebrow: "By situation",
      title: "Something forced the issue",
      items: SCENARIOS.slice(0, 3),
    },
    {
      href: "/solutions#surfaces",
      eyebrow: "By surface",
      title: "You know the gap already",
      items: SURFACES.slice(0, 3),
    },
    {
      href: "/solutions#alternatives",
      eyebrow: "By alternative",
      title: "You're comparing us to something",
      items: ALTERNATIVES.slice(0, 3),
    },
  ];
  return (
    <section className="mx-auto max-w-6xl px-5 py-20">
      <Reveal className="mx-auto mb-12 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">Where to start</span>
        <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
          What brought you here?
        </h2>
        <p className="mt-3 text-base leading-relaxed text-muted">
          People arrive at this from very different places. Pick whichever sounds like you — each one
          lands on a page written for that question, not a generic tour.
        </p>
      </Reveal>

      <Reveal delay={70} className="grid gap-5 md:grid-cols-3">
        {lanes.map((lane) => (
          <div key={lane.href} className="card flex flex-col p-6">
            <span className="text-xs font-semibold uppercase tracking-wider text-faint">{lane.eyebrow}</span>
            <h3 className="mt-2 text-lg font-semibold leading-snug">{lane.title}</h3>
            <ul className="mt-4 flex-1 space-y-2.5">
              {lane.items.map((it) => (
                <li key={it.href}>
                  <Link
                    href={it.href}
                    className="group flex items-start gap-2 text-sm leading-relaxed text-muted transition hover:text-ink"
                  >
                    <ArrowRight className="mt-1 h-3.5 w-3.5 shrink-0 text-faint transition group-hover:translate-x-0.5 group-hover:text-accent" />
                    <span>{it.label}</span>
                  </Link>
                </li>
              ))}
            </ul>
            <Link
              href={lane.href}
              className="mt-5 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline"
            >
              See all <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        ))}
      </Reveal>

      {/* FREE TOOLS, surfaced.
          These three are the best top-of-funnel assets on the site — ungated, instantly useful, and
          exactly what a visitor with a blocked deal wants before they will consider signing up. They
          lived behind a nav dropdown and one small hero link. Placed here rather than in a section of
          their own: someone who just answered "what brought you here?" and did not see themselves in
          a lane still has a reason to stay. */}
      <Reveal delay={140} className="mt-8 rounded-2xl border border-border bg-surface p-5 sm:p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="text-sm font-semibold text-ink">Not ready to sign up? Use these anyway.</div>
            <p className="mt-1 text-sm leading-relaxed text-muted">
              Free, no account, no card. They are useful whether or not you ever buy anything.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {[
              { href: "/scan", label: "Scan your domain" },
              { href: "/soc2-readiness", label: "SOC 2 readiness check" },
              { href: "/sample-report", label: "See a real VAPT report" },
            ].map((t) => (
              <Link
                key={t.href}
                href={t.href}
                className="inline-flex items-center gap-1.5 rounded-xl border border-accent/30 bg-accent-soft px-3.5 py-2 text-sm font-semibold text-accent transition hover:border-accent/60"
              >
                {t.label} <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            ))}
          </div>
        </div>
      </Reveal>
    </section>
  );
}

// Compare — the category wedge. SMB buyers are choosing between a compliance platform, a
// point scanner, and hiring. We're the one box that does all three, autonomously. Honest
// category comparison (capabilities vary by vendor/plan — footnoted), no fabricated metrics.
// Still rendered on /pricing and /vapt, where a buyer is explicitly weighing options; it left the
// homepage because a cold visitor hasn't yet decided they're shopping in this category at all.
function Compare() {
  const cols = [
    { name: "TensorShield", sub: "the autonomous team", highlight: true },
    { name: "Compliance platforms", sub: "Vanta · Drata", highlight: false },
    { name: "Point scanners", sub: "Snyk · Dependabot", highlight: false },
    { name: "Hire an engineer", sub: "$150k+/yr", highlight: false },
  ];
  // cell value: "yes" | "no" | "part" | a literal string (rendered as text)
  const rows: { label: string; cells: (string)[] }[] = [
    { label: "Deep detection — code, cloud, web, identity", cells: ["yes", "part", "part", "yes"] },
    { label: "Ships the actual fix (PR / config change)", cells: ["yes", "no", "no", "yes"] },
    { label: `Compliance evidence — ${FRAMEWORK_COUNT} frameworks, signed`, cells: ["yes", "yes", "no", "part"] },
    { label: "Identity & email-spoofing posture", cells: ["yes", "part", "no", "yes"] },
    { label: "Runs 24/7, autonomous, human-gated", cells: ["yes", "no", "no", "no"] },
    { label: "Cost for an SMB", cells: ["$/mo", "$$/mo", "$/mo", "$$$$/yr"] },
  ];
  return (
    <section className="mx-auto max-w-6xl px-5 py-20">
      <div className="mx-auto mb-12 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">Why TensorShield</span>
        <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
          One platform where you&apos;d otherwise stitch three — or hire.
        </h2>
        <p className="mt-3 text-base leading-relaxed text-muted">
          Most SMBs end up paying for a compliance tool, a scanner, and the engineer to run both. TensorShield is the one
          box that detects, fixes, and proves — with you approving anything that matters.
        </p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] border-separate border-spacing-0 text-sm">
          <thead>
            <tr>
              <th className="w-[34%] p-0" />
              {cols.map((c) => (
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
            {rows.map((r, ri) => (
              <tr key={r.label}>
                <td className="border-t border-border py-3 pr-4 text-sm text-ink">{r.label}</td>
                {r.cells.map((v, ci) => (
                  <td
                    key={ci}
                    className={`border-t border-border px-4 py-3 text-center ${
                      cols[ci].highlight ? "bg-accent-soft/30" : ""
                    } ${ri === rows.length - 1 ? "rounded-b-xl" : ""}`}
                  >
                    <CompareCell v={v} highlight={cols[ci].highlight} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-4 text-center text-[11px] text-faint">
        Category comparison — capabilities vary by vendor and plan. Vanta &amp; Drata are compliance-automation platforms;
        Snyk &amp; Dependabot are code/dependency scanners.
      </p>

      {/* ROI band */}
      <div className="mt-10 flex flex-col items-center gap-4 rounded-2xl border border-accent/30 bg-accent-soft/30 px-6 py-8 text-center sm:flex-row sm:text-left">
        <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-accent text-white shadow-sm">
          <Wallet className="h-6 w-6" />
        </span>
        <div className="flex-1">
          <div className="text-lg font-semibold tracking-tight">A fraction of a hire — that never sleeps, takes PTO, or quits.</div>
          <p className="mt-1 text-sm leading-relaxed text-muted">
            A mid-level security engineer runs $150k+/yr and can&apos;t cover detection, compliance, and identity alone.
            TensorShield does all three continuously, and only pulls in a human for the calls that need judgment.
          </p>
        </div>
        <Link
          href="/pricing"
          className="inline-flex shrink-0 items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
        >
          See pricing <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
    </section>
  );
}

function CompareCell({ v, highlight }: { v: string; highlight: boolean }) {
  if (v === "yes") return <CheckCircle2 className={`mx-auto h-5 w-5 ${highlight ? "text-pulse" : "text-pulse/80"}`} />;
  if (v === "no") return <XCircle className="mx-auto h-5 w-5 text-faint/60" />;
  if (v === "part") return <Minus className="mx-auto h-5 w-5 text-amber-500/70" />;
  // literal text (e.g. cost)
  return <span className={`text-sm font-semibold ${highlight ? "text-accent" : "text-muted"}`}>{v}</span>;
}

function Section({ eyebrow, title, sub, children }: { eyebrow: string; title: string; sub: string; children: React.ReactNode }) {
  return (
    <div className="mx-auto max-w-6xl px-5 py-20">
      <Reveal className="mx-auto mb-12 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">{eyebrow}</span>
        <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">{title}</h2>
        <p className="mt-3 text-base leading-relaxed text-muted">{sub}</p>
      </Reveal>
      <Reveal delay={90}>{children}</Reveal>
    </div>
  );
}

// The hero pipeline: your stack → TensorShield → outcomes. Communicates the value prop at
// a glance — and leads with the wedge (we ship fixes, not just findings).
function StackPipeline() {
  const stack = [
    { icon: Cloud, label: "Cloud", sub: "AWS · GCP · Azure" },
    { icon: Mail, label: "Workspace", sub: "Google · M365" },
    { icon: GitBranch, label: "Code", sub: "GitHub · GitLab" },
    { icon: KeyRound, label: "Identity & MFA", sub: "Okta · SSO" },
  ];
  const outcomes = [
    { icon: Wrench, label: "Fixes shipped", sub: "PRs & configs, gated", strong: true },
    { icon: FileCheck2, label: `${FRAMEWORK_COUNT} frameworks mapped`, sub: `SOC 2 · ISO · GDPR · +${FRAMEWORK_COUNT - 3}` },
    { icon: Lock, label: "Signed evidence pack", sub: "reproducible, not screenshots" },
    { icon: ClipboardCheck, label: "Auditor-ready report", sub: "PDF · Markdown · CSV" },
    { icon: Activity, label: "Live posture dashboard", sub: "continuous, 24/7" },
  ];
  return (
    <div className="mx-auto mt-16 max-w-5xl">
      <div className="card grid items-stretch gap-4 p-5 shadow-elevated md:grid-cols-[1fr_auto_1fr_auto_1.15fr] md:gap-2 md:p-6">
        {/* Your stack */}
        <Column heading="Your stack">
          {stack.map(({ icon: Icon, label, sub }) => (
            <Node key={label} Icon={Icon} label={label} sub={sub} />
          ))}
        </Column>

        <Connector />

        {/* TensorShield — the live core: a breathing glow + a pulsing ring around the shield */}
        <div className="flex items-center">
          <div className="w-full rounded-2xl border border-accent/40 bg-accent-soft/40 p-5 text-center animate-glow-pulse">
            <span className="relative mx-auto grid h-11 w-11 place-items-center rounded-xl bg-accent text-white shadow-sm">
              <span className="absolute inset-0 rounded-xl bg-accent/40 animate-ping" />
              <ShieldCheck className="relative h-5 w-5" />
            </span>
            <div className="mt-3 text-base font-semibold">TensorShield</div>
            <div className="mt-1 text-xs font-medium text-accent">Detect · Triage · Fix · Prove</div>
            <div className="mt-2 text-[11px] leading-relaxed text-muted">automated, with a human in the loop</div>
          </div>
        </div>

        <Connector delay={1.3} />

        {/* Outcomes */}
        <Column heading="What you get">
          {outcomes.map(({ icon: Icon, label, sub, strong }) => (
            <Node key={label} Icon={Icon} label={label} sub={sub} strong={strong} />
          ))}
        </Column>
      </div>
      <p className="mt-4 text-center text-xs text-faint">
        Read-only by default · nothing changes without your approval · your data is never mixed with another customer’s · signed evidence
      </p>
    </div>
  );
}

function Column({ heading, children }: { heading: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col">
      <div className="mb-2 text-center text-[10px] font-semibold uppercase tracking-wider text-faint md:text-left">{heading}</div>
      <div className="flex flex-1 flex-col gap-2">{children}</div>
    </div>
  );
}

function Node({ Icon, label, sub, strong }: { Icon: typeof Cloud; label: string; sub: string; strong?: boolean }) {
  return (
    <div
      className={`flex items-center gap-2.5 rounded-xl border px-3 py-2 text-left ${
        strong ? "border-accent/40 bg-accent-soft/40" : "border-border bg-surface"
      }`}
    >
      <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-lg ${strong ? "bg-accent text-white" : "bg-surface-2 text-muted"}`}>
        <Icon className="h-3.5 w-3.5" />
      </span>
      <span className="min-w-0">
        <span className={`block truncate text-xs font-semibold ${strong ? "text-accent" : "text-ink"}`}>{label}</span>
        <span className="block truncate text-[10px] text-faint">{sub}</span>
      </span>
    </div>
  );
}

// Live connector between columns — a highlight dot streams left→right along the track on desktop
// (data flowing into the agent and back out as fixes); a down-chevron on mobile. The `delay`
// staggers the two connectors so the pulse appears to travel through TensorShield.
function Connector({ delay = 0 }: { delay?: number }) {
  return (
    <div className="flex items-center justify-center text-faint">
      <div className="relative hidden h-px w-10 overflow-visible bg-gradient-to-r from-border via-accent/40 to-border md:block">
        <span
          className="absolute top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent shadow-[0_0_8px_rgba(79,70,229,0.7)] animate-flow-x"
          style={{ animationDelay: `${delay}s` }}
        />
      </div>
      <ChevronDown className="h-5 w-5 md:hidden" />
    </div>
  );
}

// The "connects to everything" visual for the trust section.
function ConnectorsVisual() {
  const items: { icon?: typeof FileCheck2; brand?: string; label: string }[] = [
    { brand: "github", label: "GitHub" },
    { brand: "aws", label: "AWS" },
    { brand: "okta", label: "Okta" },
    { icon: FileCheck2, label: "SOC 2" },
    { icon: Lock, label: "Signed" },
    { icon: Star, label: "Trust" },
  ];
  return (
    <div className="card relative grid grid-cols-3 gap-3 p-6">
      {items.map(({ icon: Icon, brand, label }) => (
        <div key={label} className="flex flex-col items-center gap-2 rounded-xl border border-border bg-bg py-5 text-center">
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-surface text-ink shadow-sm">
            {brand ? <ProviderIcon kind={brand} className="h-4 w-4" /> : Icon ? <Icon className="h-4 w-4" /> : null}
          </span>
          <span className="text-[11px] font-medium text-muted">{label}</span>
        </div>
      ))}
    </div>
  );
}

// One agent, one line: mark, name, job. The hero's job is to be understood at a glance, and two of
// these are read faster than the sentence they replaced — the reader sees that there are exactly two
// things and what each does, without parsing prose.
function AgentLine({ Icon, name, job }: { Icon: typeof ShieldCheck; name: string; job: string }) {
  return (
    <div className="flex items-start gap-2.5 text-left">
      <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
        <Icon className="h-3.5 w-3.5" />
      </span>
      <p className="text-sm leading-relaxed text-muted">
        <span className="font-medium text-ink">{name}</span> — {job}
      </p>
    </div>
  );
}
