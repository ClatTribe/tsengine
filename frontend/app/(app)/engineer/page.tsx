import Link from "next/link";
import { Sparkles, Cloud, Code2, ShieldCheck, Wrench, ArrowUpRight, Search, ListFilter, Inbox } from "lucide-react";
import { api } from "@/lib/api";
import { PageIntro } from "@/components/ui/page-intro";
import { GenerateBrief } from "@/components/brief/generate-brief";
import { lastTriage } from "../brief/actions";
import { AskEstate } from "@/components/engineer/ask-estate";
import { timeAgo } from "@/lib/utils";

export const dynamic = "force-dynamic";

// /engineer — the AI Security Engineer's console: ONE place with everything the defence job needs.
//
// It is one of the two products the platform sells, and until now it was the only one with no way in.
// The AI Pentester had a nav row and a page; the engineer's console lived at /brief, reachable from an
// action strip and the command palette — the two depth specialists even linked "back to the AI Security
// Engineer" at a destination the navigation never offered. Same console, given a front door.
//
// Ordered by how the job actually starts: ASK first (the question an engineer opens with — "are we
// exposed to X?"), then the scope it reasons over, then TRIAGE, then what is waiting on a human, then
// the depth specialists. Agentic ACTION cards, not a chat box (docs/product-restructure.md).
// It is NOT just a fix button — it does three jobs: (1) INVESTIGATE deeper / better detection (the cloud
// agent FINDS attack paths a routine scan misses via cloud/investigate; l2/translate chains across
// surfaces), (2) TRIAGE/prioritize — cut the noise to what's actually exploitable, (3) FIX (per-finding
// autofix + compliance remediation). Each action runs a bounded agent over the tenant's REAL findings;
// grounded (§10 — never fabricates), and anything it would change routes through the HITL gate.
const ACTIONS = [
  {
    href: "/code-engineer",
    icon: Code2,
    title: "Code deep-dive",
    desc: "Run the code specialist over your source — is a finding actually exploitable, a leaked secret's blast radius, and the right-layer fix a scanner can't give.",
  },
  {
    href: "/cloud-engineer",
    icon: Cloud,
    title: "Cloud deep-dive",
    desc: "Run the cloud specialist over your cloud graph — IAM effective permissions, reachability, and the attack paths that actually reach a crown jewel.",
  },
  {
    href: "/compliance",
    icon: ShieldCheck,
    title: "Compliance fixes & evidence",
    desc: "Turn each control gap into concrete, grounded remediation steps and signed, auditor-ready evidence.",
  },
  {
    href: "/issues",
    icon: Wrench,
    title: "Auto-fix a finding",
    desc: "Open an issue and hit Fix — the engineer generates the patch (PR / config) and routes it to you for approval.",
  },
];

export default async function EngineerConsolePage() {
  // Scope so the founder sees WHAT the engineer reasons over (coverage honesty) before triggering an action.
  const [findings, assets, engagements, priorBrief, approvals] = await Promise.all([
    api.findings(), api.assets(), api.engagements(), lastTriage(), api.approvals(),
  ]);
  const freshest = engagements.map((e) => e.completed_at).filter(Boolean).sort().pop();

  return (
    <div className="space-y-8">
      <PageIntro
        icon={Sparkles}
        title="AI Security Engineer"
        description="More than a fix button. Your AI security engineer does three jobs: investigates deeper to surface what a routine scan missed, prioritizes what's actually exploitable, then proposes the fix. Pick an action — it reasons over your real findings, grounded in evidence (nothing invented), and anything it would change routes to you (or your expert) for approval."
      />

      {/* ASK FIRST. The question the job actually opens with, and the one capability the agent had
          all along that no human could reach. */}
      <AskEstate />

      {/* The three jobs, named — so the console doesn't read as fix-only. */}
      <div className="grid gap-2.5 sm:grid-cols-3">
        {[
          { icon: Search, label: "Investigate deeper", desc: "Re-probes and chains across surfaces — finds what a routine scan missed." },
          { icon: ListFilter, label: "Prioritize the real risk", desc: "Cuts the noise to what's actually exploitable, ranked." },
          { icon: Wrench, label: "Propose the fix", desc: "Generates the patch / config — for your approval, never auto-applied." },
        ].map(({ icon: Icon, label, desc }) => (
          <div key={label} className="card flex flex-col gap-1.5 p-4">
            <span className="inline-flex items-center gap-2 text-sm font-medium text-ink"><Icon className="h-4 w-4 text-accent" /> {label}</span>
            <span className="text-xs leading-relaxed text-muted">{desc}</span>
          </div>
        ))}
      </div>
      {findings.length > 0 && (
        <p className="text-xs leading-relaxed text-muted">
          Reasoning over{" "}
          <span className="font-medium text-ink">{findings.length} finding{findings.length === 1 ? "" : "s"}</span> across{" "}
          <span className="font-medium text-ink">{assets.length} asset{assets.length === 1 ? "" : "s"}</span>
          {freshest ? <> · freshest scan {timeAgo(freshest)}</> : null}.
        </p>
      )}

      {/* Primary agentic action — Triage & brief (the l2 translate agent over the whole estate). */}
      <section className="rounded-2xl border border-accent/30 bg-accent-soft/20 p-5">
        <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-accent">Triage &amp; prioritize</div>
        <p className="mb-4 text-sm leading-relaxed text-muted">
          One click: the engineer prioritizes everything that matters, chains it across surfaces, and writes a
          plain-English brief you can forward to a board, an investor, or a customer.
        </p>
        <GenerateBrief initial={priorBrief} />
      </section>

      {/* WHAT NEEDS YOU. The engineer proposes; a human approves. Surfacing the queue here means the
          console shows the whole loop rather than only the half the agent does. */}
      {approvals.length > 0 && (
        <Link
          href="/inbox"
          className="card group flex items-center gap-3 border-accent/30 bg-accent-soft/20 p-4 transition hover:border-accent/50"
        >
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
            <Inbox className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium text-ink">
              {approvals.length} change{approvals.length === 1 ? "" : "s"} waiting on you
            </div>
            <div className="text-xs leading-relaxed text-muted">
              The engineer prepared {approvals.length === 1 ? "it" : "them"} and stopped. Review the diff, then approve or reject.
            </div>
          </div>
          <ArrowUpRight className="h-4 w-4 shrink-0 text-faint transition group-hover:text-accent" />
        </Link>
      )}

      {/* More agentic actions — each triggers a real agent over your findings (not a chat). */}
      <section>
        <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-faint">More actions</div>
        <div className="grid gap-2.5 sm:grid-cols-2">
          {ACTIONS.map(({ href, icon: Icon, title, desc }) => (
            <Link key={href} href={href} className="card group flex items-start gap-3 p-4 transition hover:border-accent/40">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium text-ink">{title}</div>
                <div className="text-xs leading-relaxed text-muted">{desc}</div>
              </div>
              <ArrowUpRight className="mt-0.5 h-4 w-4 shrink-0 text-faint transition group-hover:text-accent" />
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}
