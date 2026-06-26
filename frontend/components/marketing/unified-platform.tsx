import { Bot, Crosshair, Boxes, AppWindow, GitBranch, Server, ArrowDown, Layers, Spline, FileCheck2 } from "lucide-react";
import { Reveal } from "@/components/marketing/reveal";

// UnifiedPlatform — the "it's one brain, not point tools" section. Shows every product + asset feeding
// ONE finding graph (crossdetect + grc), which corroborates, correlates across surfaces, and rolls up
// into one signed compliance posture. Grounded: the only number shown is "22 frameworks" (real); no
// per-tenant demo counts.
const SOURCES = [
  { icon: Bot, label: "AI security engineer" },
  { icon: Crosshair, label: "AI pentest" },
  { icon: Boxes, label: "Supply-chain" },
  { icon: AppWindow, label: "SaaS & identity" },
  { icon: GitBranch, label: "CI/CD" },
  { icon: Server, label: "8 asset-type scans" },
];

const OUTCOMES = [
  {
    icon: Layers,
    title: "Better detection",
    body: "The same issue found by two scanners collapses into one — and is marked confirmed when independent tools agree. Less noise, higher confidence.",
  },
  {
    icon: Spline,
    title: "Cross-asset attack paths",
    body: "A web flaw that leaks a key, chained to the cloud account it unlocks. Findings bridge surfaces through a real shared entity — across all 8 asset types.",
  },
  {
    icon: FileCheck2,
    title: "One compliance posture",
    body: "Every product's findings map to controls and roll into a single signed posture across all 22 frameworks — so detection and audit-readiness move together.",
  },
];

export function UnifiedPlatform() {
  return (
    <section className="border-y border-border bg-surface">
      <div className="mx-auto max-w-5xl px-5 py-16">
        <Reveal className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">One platform, one brain</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
            Every signal makes the next one smarter.
          </h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            The products aren&apos;t separate tools bolted together. Every scan, pentest, and posture check feeds one
            finding graph — so they corroborate each other&apos;s detections and roll into a single compliance posture.
          </p>
        </Reveal>

        {/* sources */}
        <Reveal delay={80} className="mx-auto flex max-w-3xl flex-wrap justify-center gap-2.5">
          {SOURCES.map(({ icon: Icon, label }) => (
            <span
              key={label}
              className="inline-flex items-center gap-2 rounded-full border border-border bg-bg px-3.5 py-1.5 text-sm text-ink shadow-sm"
            >
              <Icon className="h-3.5 w-3.5 text-accent" /> {label}
            </span>
          ))}
        </Reveal>

        {/* convergence */}
        <Reveal delay={140} className="mt-6 flex flex-col items-center">
          <ArrowDown className="h-5 w-5 text-faint" />
          <div className="mt-2 w-full max-w-xl rounded-2xl border-2 border-accent/40 bg-accent-soft/30 p-5 text-center">
            <div className="text-sm font-semibold text-accent">One finding graph — the shared brain</div>
            <p className="mx-auto mt-1.5 max-w-md text-sm leading-relaxed text-muted">
              Corroborate findings across tools · correlate cross-surface attack paths via a shared entity ·
              map every finding to compliance controls · the pentest writes proof back onto the finding.
            </p>
          </div>
          <ArrowDown className="mt-3 h-5 w-5 text-faint" />
        </Reveal>

        {/* outcomes */}
        <Reveal delay={200} className="mt-3 grid gap-4 md:grid-cols-3">
          {OUTCOMES.map(({ icon: Icon, title, body }) => (
            <div key={title} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <h3 className="mt-3.5 text-sm font-semibold">{title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{body}</p>
            </div>
          ))}
        </Reveal>
      </div>
    </section>
  );
}
