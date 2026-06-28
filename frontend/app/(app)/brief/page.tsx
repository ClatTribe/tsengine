import Link from "next/link";
import { FileText, Cloud, ArrowUpRight } from "lucide-react";
import { api } from "@/lib/api";
import { PageIntro } from "@/components/ui/page-intro";
import { GenerateBrief } from "@/components/brief/generate-brief";
import { timeAgo } from "@/lib/utils";

export const dynamic = "force-dynamic";

// The plain-English security brief — the L2 Lead/translator turns the raw findings into the deliverable
// a founder / non-security team can actually act on (exec summary, what to do next, prioritized issues).
export default async function BriefPage() {
  // Fetch the scope so the founder sees WHAT the brief covers + how fresh the data is BEFORE generating —
  // a brief built on a stale or empty scan should say so (coverage honesty), not look authoritative by default.
  const [findings, assets, engagements] = await Promise.all([api.findings(), api.assets(), api.engagements()]);
  const freshest = engagements.map((e) => e.completed_at).filter(Boolean).sort().pop();

  return (
    <div className="space-y-8">
      <PageIntro
        icon={FileText}
        title="Plain-English brief"
        description="Your findings, translated by the AI security engineer into a report a non-security team can act on — an executive summary, the prioritized issues that actually matter, and what to do next. The same grounded findings, explained in plain English. Whoever owns the judgment (your team, your MSP's expert, or our hired expert) reviews it and signs off."
      />
      {findings.length > 0 && (
        <p className="text-xs leading-relaxed text-muted">
          This brief will cover{" "}
          <span className="font-medium text-ink">{findings.length} finding{findings.length === 1 ? "" : "s"}</span> across{" "}
          <span className="font-medium text-ink">{assets.length} monitored asset{assets.length === 1 ? "" : "s"}</span>
          {freshest ? <> · freshest scan {timeAgo(freshest)}</> : null}.
        </p>
      )}
      <GenerateBrief />

      {/* The engineer delegates deep cloud-graph reasoning to the cloud specialist (the investigate_cloud
          tool, #727) — surfaced here so it reads as a depth lens of THIS engineer, not a separate persona. */}
      <Link
        href="/cloud-engineer"
        className="group flex items-center gap-3 rounded-xl border border-border bg-surface p-4 transition hover:border-accent/40"
      >
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
          <Cloud className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-ink">Cloud depth</div>
          <div className="text-xs text-muted">
            For IAM effective permissions, reachability, and proven attack paths, the engineer delegates to the cloud specialist.
          </div>
        </div>
        <ArrowUpRight className="h-4 w-4 shrink-0 text-faint transition group-hover:text-accent" />
      </Link>
    </div>
  );
}
