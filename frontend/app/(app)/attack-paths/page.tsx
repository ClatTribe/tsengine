import { Spline, Crown, ArrowRight, Globe, Cloud, GitBranch, Server, Network, Smartphone, KeyRound, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import type { AttackPath, AttackStep } from "@/lib/types";
import { SeverityBadge, Empty } from "@/components/ui/primitives";

export const dynamic = "force-dynamic";

export default async function AttackPathsPage() {
  const { attack_paths: paths } = await api.attackPaths();
  const sorted = [...paths].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">Attack paths</h1>
          <p className="max-w-2xl text-xs text-muted">
            Cross-surface correlation — how a single weakness on one surface chains, through a shared
            identifier, to a crown jewel on another. Every hop is grounded in a real shared entity (a leaked
            key, an ARN, a host); nothing is inferred.
          </p>
        </div>
        <div className="text-right">
          <span className="text-xl font-semibold text-high">{paths.length}</span>{" "}
          <span className="text-xs text-faint">path{paths.length === 1 ? "" : "s"}</span>
        </div>
      </div>

      {sorted.length === 0 ? (
        <Empty>
          No cross-surface attack paths right now. A path appears when one finding bridges — via a shared key,
          host, or resource — to a higher-value target on a different surface. Connect more surfaces (code,
          cloud, web) to widen the correlation.
        </Empty>
      ) : (
        <div className="space-y-4">
          {sorted.map((p, i) => (
            <PathCard key={i} path={p} />
          ))}
        </div>
      )}
    </div>
  );
}

function PathCard({ path }: { path: AttackPath }) {
  return (
    <div className="card p-5">
      <div className="mb-4 flex items-center gap-2">
        <Spline className="h-4 w-4 text-accent" />
        <SeverityBadge severity={path.severity} />
        <span className="text-sm font-medium">
          {path.steps.length}-step path → {path.steps[path.steps.length - 1]?.asset_type.replace(/_/g, " ")}
        </span>
      </div>

      {/* The chain, left-to-right, wrapping on small screens. */}
      <div className="flex flex-wrap items-stretch gap-y-3">
        {path.steps.map((s, i) => (
          <div key={i} className="flex items-stretch">
            <StepCard step={s} entry={i === 0} />
            {i < path.steps.length - 1 && <Connector via={s.via_entity} />}
          </div>
        ))}
      </div>
    </div>
  );
}

function StepCard({ step, entry }: { step: AttackStep; entry: boolean }) {
  const Icon = assetIcon(step.asset_type);
  return (
    <div
      className={`flex w-56 flex-col rounded-lg border p-3 ${
        step.crown_jewel ? "border-high/50 bg-high/5" : entry ? "border-accent/40 bg-accent-soft/30" : "border-border bg-surface"
      }`}
    >
      <div className="mb-1.5 flex items-center gap-1.5">
        {step.crown_jewel ? <Crown className="h-3.5 w-3.5 text-high" /> : <Icon className="h-3.5 w-3.5 text-muted" />}
        <span className="mono text-[10px] uppercase tracking-wide text-faint">
          {entry ? "entry · " : ""}
          {step.crown_jewel ? "crown jewel · " : ""}
          {step.asset_type.replace(/_/g, " ")}
        </span>
      </div>
      <div className="flex items-center gap-1.5">
        <SeverityBadge severity={step.severity} className="scale-90" />
        {step.verified && (
          <span className="inline-flex items-center gap-0.5 text-[10px] font-medium text-pulse">
            <ShieldCheck className="h-3 w-3" /> verified
          </span>
        )}
      </div>
      <a href={`/findings/${step.finding_id}`} className="mt-1.5 line-clamp-2 text-xs leading-snug hover:text-accent">
        {step.title}
      </a>
      {step.asset_target && <div className="mono mt-1 truncate text-[10px] text-faint">{step.asset_target}</div>}
    </div>
  );
}

// Connector renders the arrow between two steps, labeled with the shared entity
// that bridges them (the grounding for the hop).
function Connector({ via }: { via?: string }) {
  return (
    <div className="flex w-20 shrink-0 flex-col items-center justify-center px-1 text-center">
      <ArrowRight className="h-4 w-4 text-faint" />
      {via && (
        <span className="mt-1 inline-flex items-center gap-0.5 text-[9px] leading-tight text-muted">
          <KeyRound className="h-2.5 w-2.5 shrink-0 text-accent" />
          <span className="break-all">{via}</span>
        </span>
      )}
    </div>
  );
}

function assetIcon(type: string) {
  switch (type) {
    case "web_application":
    case "api":
      return Globe;
    case "cloud_account":
      return Cloud;
    case "repository":
      return GitBranch;
    case "container_image":
      return Server;
    case "ip_address":
    case "domain":
      return Network;
    case "mobile_application":
      return Smartphone;
    default:
      return Server;
  }
}

const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
function sevRank(s: string): number {
  return (SEV as Record<string, number>)[s?.toLowerCase()] ?? 5;
}
