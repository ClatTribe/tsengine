import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import {
  ShieldCheck, Power, Crosshair, Boxes, ScrollText, UserCheck, ShieldAlert, MapPin, Fingerprint,
  ArrowRight, CheckCircle2, CircleDashed,
} from "lucide-react";

export const metadata = pageMeta({
  title: "AI agent controls — TensorShield",
  description:
    "The controls security leaders require before they'll trust an AI to test their systems: a kill-switch, hard scope enforcement, agent/tool isolation, full signed logging, a human gate, and prompt-injection resistance. Built into TensorShield by construction.",
  path: "/agent-controls",
});

// The 8 controls security leaders said must be built into an AI security system BEFORE they would
// trust AI-driven pentesting (2026 industry survey of 400 security + engineering leaders, p35: "build
// hard boundaries into the system rather than rely on a human in the loop for every step"). Each is
// mapped to the TensorShield mechanism that enforces it — grounded, not aspirational: `met:false`
// marks the one we strengthen honestly (proof-of-ownership) rather than overclaim.
const CONTROLS: {
  icon: typeof Power;
  demand: string; // what leaders require
  pct: string; // % of leaders who named it
  how: string; // how we enforce it
  mech: string; // the concrete mechanism
  met: boolean;
}[] = [
  {
    icon: Power, demand: "Ability to terminate all activity", pct: "39%",
    how: "A global kill-switch freezes every autonomous action for your whole org instantly. It fails closed — the switch beats any pending approval; queued actions wait until a human disengages it.",
    mech: "Kill-switch · per-connection quarantine", met: true,
  },
  {
    icon: MapPin, demand: "Data residency guarantees", pct: "38%",
    how: "Self-host on your own cloud (AWS/Supabase in your account) so data never leaves your boundary. World-state intel is shared and global; your findings, exposure, and incidents stay strictly tenant-isolated.",
    mech: "Tenant isolation · self-hosted deploy", met: true,
  },
  {
    icon: UserCheck, demand: "Human oversight / review checkpoint", pct: "37%",
    how: "Consequential changes pause at a human-gated desk before anything is applied — tier-gated, with irreversible/legal actions requiring a named human's signature that can never be auto-approved.",
    mech: "HITL desk · tier gates · named sign-off", met: true,
  },
  {
    icon: ScrollText, demand: "Full logging of all actions", pct: "36%",
    how: "Every decision — automated or human — is recorded into a signed, replayable ledger (ed25519 over canonical contents). The same scheme covers your compliance evidence, so one verifier checks both.",
    mech: "Signed decision ledger", met: true,
  },
  {
    icon: ShieldAlert, demand: "Controls against prompt injection", pct: "35%",
    how: "The model only ever proposes; a deterministic predicate disposes. A prompt-injected agent literally cannot record a finding or take an action a tool didn't prove — so injection widens nothing it shouldn't.",
    mech: "Propose-vs-dispose · instruction-source boundary", met: true,
  },
  {
    icon: Crosshair, demand: "Hard technical scope enforcement", pct: "32%",
    how: "A rules-of-engagement guard gates every agent action against the engagement's scope and budget, with an absolute destructive-action ban and explicit-consent gating for active exploitation.",
    mech: "Rules-of-Engagement guard · SSRF screen", met: true,
  },
  {
    icon: Boxes, demand: "Isolation between agent and tools", pct: "30%",
    how: "The orchestrating agent never holds the tools or the host. Scanners run in per-scan sandbox containers on an isolated network, reached through a de-privileged Docker proxy — not a raw socket.",
    mech: "Host/sandbox boundary · socket proxy", met: true,
  },
  {
    icon: Fingerprint, demand: "Proof of asset ownership", pct: "36%",
    how: "Connected systems prove ownership through their own OAuth consent, and active exploitation requires a recorded, named authorization. An explicit DNS/file ownership challenge for standalone targets is rolling out.",
    mech: "OAuth consent · recorded authorization", met: false,
  },
];

export default function AgentControls() {
  const met = CONTROLS.filter((c) => c.met).length;
  return (
    <>
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <ShieldCheck className="h-3.5 w-3.5 text-accent" /> Safe by construction
          </span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-5xl">
            An AI you can let off the leash — because it&apos;s on rails.
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            Security leaders won&apos;t trust an AI to touch production until the guardrails are built into the system, not
            bolted on. We started there. Here are the controls they ask for — and exactly how TensorShield enforces each one.
          </p>
        </div>
      </section>

      {/* The mapping: each demanded control → our mechanism */}
      <section className="mx-auto max-w-5xl px-5 pb-4">
        <p className="mb-5 text-center text-xs uppercase tracking-wider text-faint">
          What leaders require before trusting AI pentesting — and how we enforce it
        </p>
        <div className="grid gap-4 md:grid-cols-2">
          {CONTROLS.map(({ icon: Icon, demand, pct, how, mech, met: ok }) => (
            <div key={demand} className="card flex gap-4 p-5">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold">{demand}</h3>
                  <span className="shrink-0 rounded-full border border-border bg-bg px-1.5 py-0.5 text-[10px] font-medium text-muted">{pct} ask for it</span>
                </div>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{how}</p>
                <div className="mt-2.5 flex items-center gap-1.5 text-xs font-medium">
                  {ok ? (
                    <><CheckCircle2 className="h-3.5 w-3.5 text-pulse" /> <span className="text-ink">{mech}</span></>
                  ) : (
                    <><CircleDashed className="h-3.5 w-3.5 text-accent" /> <span className="text-ink">{mech}</span> <span className="text-faint">· hardening</span></>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
        <p className="mt-6 text-center text-sm text-muted">
          <span className="font-semibold text-ink">{met} of {CONTROLS.length}</span> enforced by the architecture today — the
          last is being strengthened in the open. We&apos;d rather show you the one gap than pretend it isn&apos;t there.
        </p>
      </section>

      {/* Why this matters */}
      <section className="bg-surface">
        <div className="mx-auto max-w-3xl px-5 py-20 text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">The instinct leaders have</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">Build the boundaries into the system.</h2>
          <p className="mx-auto mt-3 max-w-xl text-base leading-relaxed text-muted">
            The same research found leaders want hard, technical limits — a kill-switch, isolation, scope enforcement —
            ranked above a human babysitting every step. AI is most useful when it takes work away from people, not when it
            adds a new thing to watch. So our controls are mechanical and always-on, and the human is reserved for the calls
            only a human should make.
          </p>
        </div>
      </section>

      {/* CTA */}
      <section className="mx-auto max-w-3xl px-5 py-20 text-center">
        <h2 className="text-2xl font-semibold tracking-tight">See the controls in your own workspace.</h2>
        <p className="mx-auto mt-3 max-w-xl text-base leading-relaxed text-muted">
          The kill-switch, the signed ledger, the human gate — they&apos;re in the product from the first scan, not a
          add-on. Start free and they&apos;re already on.
        </p>
        <Link href="/signup" className="mt-7 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
          Start free <ArrowRight className="h-4 w-4" />
        </Link>
      </section>
    </>
  );
}
