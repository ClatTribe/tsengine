import { Sparkles, Wrench, Crosshair, Cloud, FileCheck2, ListChecks } from "lucide-react";
import { Reveal } from "@/components/marketing/reveal";

// AgenticActions — the product's interaction model made concrete: one-click ACTIONS, not a chat box.
// Mirrors the in-app AI Security Engineer + AI Pentester consoles (docs/product-restructure.md). Each
// "button" triggers a real agent over your real findings — the differentiator vs a blank prompt (the
// Aikido AutoFix / MS Security Copilot promptbook pattern, not the Wiz query-language trap).
const ACTIONS = [
  { icon: ListChecks, label: "Triage everything", out: "A prioritized list — real risk first, the noise collapsed." },
  { icon: Wrench, label: "Auto-fix the criticals", out: "A pull request or config change, ready for you to approve." },
  { icon: Sparkles, label: "Investigate this issue", out: "Root cause, blast radius, and how it chains to a crown jewel." },
  { icon: Cloud, label: "Cloud deep-dive", out: "The IAM + reachability paths an attacker could actually use." },
  { icon: FileCheck2, label: "Generate evidence", out: "A signed, auditor-ready compliance pack." },
  { icon: Crosshair, label: "Launch a pentest", out: "An exploitation-proven report with captured PoCs." },
];

export function AgenticActions() {
  return (
    <section className="mx-auto max-w-6xl px-5 py-20">
      <Reveal className="mx-auto mb-10 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">One click, not a chat box</span>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
          An AI security team you run with actions, not prompts.
        </h2>
        <p className="mt-3 text-base leading-relaxed text-muted">
          No blank prompt to stare at. Your AI Security Engineer and AI Pentester are consoles of one-click
          actions — each triggers a real agent over your real findings, and anything it changes waits for your approval.
        </p>
      </Reveal>
      <Reveal delay={80} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {ACTIONS.map(({ icon: Icon, label, out }) => (
          <div key={label} className="card flex flex-col gap-3 p-5">
            <span className="inline-flex w-fit items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3 py-1.5 text-sm font-medium text-accent">
              <Icon className="h-4 w-4" /> {label}
            </span>
            <p className="text-sm leading-relaxed text-muted">
              <span className="text-faint">→</span> {out}
            </p>
          </div>
        ))}
      </Reveal>
    </section>
  );
}
