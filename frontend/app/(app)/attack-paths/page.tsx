import { Spline, Crown, ArrowRight, Globe, Cloud, GitBranch, Server, Network, Smartphone, KeyRound, ShieldCheck, ShieldAlert, Bug } from "lucide-react";
import { api } from "@/lib/api";
import type { AttackPath, AttackStep } from "@/lib/types";
import { SeverityBadge } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";

export const dynamic = "force-dynamic";

export default async function AttackPathsPage() {
  const { attack_paths: paths } = await api.attackPaths();
  const sorted = [...paths].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));

  return (
    <div className="space-y-6">
      <PageIntro
        icon={Spline}
        title="Attack paths"
        description="See how an attacker could chain a small issue in one place into a serious breach somewhere else — so you can cut the chain at its weakest link instead of chasing every alert."
        right={
          paths.length > 0 ? (
            <>
              <div className="text-2xl font-semibold text-high">{paths.length}</div>
              <div className="text-[11px] text-faint">path{paths.length === 1 ? "" : "s"} found</div>
            </>
          ) : undefined
        }
      />

      {/* Always-on explainer so the page is self-evident even at zero paths. */}
      <HowItWorks />

      {sorted.length === 0 ? (
        <div className="space-y-3">
          <div className="rounded-xl border border-dashed border-border bg-surface px-5 py-4 text-sm text-muted">
            <span className="font-medium text-ink">No attack paths right now — that&apos;s good.</span> It means no
            single weakness currently chains all the way to something valuable. Connect more of your stack (code,
            cloud, web, apps) so we can spot chains the moment one appears. Here&apos;s what one looks like:
          </div>
          <PathCard path={EXAMPLE_PATH} example />
        </div>
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

// HowItWorks is a compact, plain-English "what is this" strip — a weakness, a real shared
// link, a crown jewel. Keeps the page understandable to non-security readers.
function HowItWorks() {
  return (
    <div className="card flex flex-col gap-3 p-4 lg:flex-row lg:items-center">
      <div className="flex flex-1 items-center gap-2">
        <Node icon={Bug} label="A weakness" sub="in code, cloud, or an app" />
        <Hop label="shares a real link" sub="a leaked key, host, or ARN" />
        <Node icon={Crown} label="reaches a crown jewel" sub="customer data, admin, secrets" tone="high" />
      </div>
      <p className="max-w-md text-xs leading-relaxed text-muted lg:border-l lg:border-border lg:pl-4">
        When findings on different surfaces share a <span className="text-ink">real</span> identifier and the chain
        ends somewhere valuable, that&apos;s an attack path — the route an attacker would actually take. Nothing here is
        guessed; every hop is backed by a shared entity.
      </p>
    </div>
  );
}

function Node({ icon: Icon, label, sub, tone }: { icon: typeof Bug; label: string; sub: string; tone?: "high" }) {
  return (
    <div className={`flex min-w-0 flex-1 items-start gap-2 rounded-lg border p-2.5 ${tone === "high" ? "border-high/40 bg-high/5" : "border-border bg-surface-2"}`}>
      <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${tone === "high" ? "text-high" : "text-accent"}`} />
      <div className="min-w-0">
        <div className="text-xs font-medium leading-tight">{label}</div>
        <div className="truncate text-[10px] text-faint">{sub}</div>
      </div>
    </div>
  );
}

function Hop({ label, sub }: { label: string; sub: string }) {
  return (
    <div className="flex shrink-0 flex-col items-center px-1 text-center">
      <ArrowRight className="h-4 w-4 text-faint" />
      <span className="mt-0.5 text-[9px] leading-tight text-muted">{label}</span>
      <span className="text-[9px] leading-tight text-faint">{sub}</span>
    </div>
  );
}

function PathCard({ path, example }: { path: AttackPath; example?: boolean }) {
  const last = path.steps[path.steps.length - 1];
  return (
    <div className={`card p-5 ${example ? "opacity-80" : ""}`}>
      <div className="mb-1 flex items-center gap-2">
        <Spline className="h-4 w-4 text-accent" />
        <SeverityBadge severity={path.severity} />
        <span className="text-sm font-medium">
          {path.steps.length}-step path → {last?.asset_type.replace(/_/g, " ")}
        </span>
        {example && <span className="rounded-full bg-surface-2 px-1.5 py-0.5 text-[10px] font-medium text-faint">Example</span>}
      </div>
      {/* Plain-English summary of the risk — what an attacker could actually do. */}
      <p className="mb-3 flex items-start gap-1.5 text-xs text-muted">
        <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-high" />
        <span>
          An attacker who exploits <span className="text-ink">{path.steps[0]?.title}</span> could pivot to{" "}
          <span className="text-ink">{last?.title}</span>. Fixing the first step breaks the chain.
        </span>
      </p>

      {/* The one recommended action: cut the chain at its entry point. Read-only paths gave the founder
          nowhere to go; this links straight to the entry finding (where the fix is queued for approval). */}
      {!example && path.steps[0]?.finding_id && (
        <a
          href={`/findings/${path.steps[0].finding_id}`}
          className="mb-4 inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white shadow-sm transition hover:bg-accent-hover"
        >
          Fix the entry point — break this chain <ArrowRight className="h-3.5 w-3.5" />
        </a>
      )}

      {/* The chain, left-to-right, wrapping on small screens. */}
      <div className="flex flex-wrap items-stretch gap-y-3">
        {path.steps.map((s, i) => (
          <div key={i} className="flex items-stretch">
            <StepCard step={s} entry={i === 0} example={example} />
            {i < path.steps.length - 1 && <Connector via={s.via_entity} />}
          </div>
        ))}
      </div>
    </div>
  );
}

function StepCard({ step, entry, example }: { step: AttackStep; entry: boolean; example?: boolean }) {
  const Icon = assetIcon(step.asset_type);
  const title = <span className="mt-1.5 line-clamp-2 text-xs leading-snug">{step.title}</span>;
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
      {example ? title : (
        <a href={`/findings/${step.finding_id}`} className="hover:text-accent">{title}</a>
      )}
      {step.asset_target && <div className="mono mt-1 truncate text-[10px] text-faint">{step.asset_target}</div>}
    </div>
  );
}

// Connector renders the arrow between two steps, labeled with the shared entity that
// bridges them (the grounding for the hop).
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

// EXAMPLE_PATH illustrates the concept on the empty state (clearly labeled "Example").
const EXAMPLE_PATH: AttackPath = {
  severity: "critical",
  steps: [
    {
      asset_type: "repository",
      title: "AWS access key hardcoded in source",
      severity: "high",
      finding_id: "",
      via_entity: "AKIA…EXAMPLE",
      asset_target: "acme/payments-api",
      crown_jewel: false,
      verified: false,
    },
    {
      asset_type: "cloud_account",
      title: "S3 bucket with customer PII — full read/write",
      severity: "critical",
      finding_id: "",
      asset_target: "arn:aws:s3:::acme-invoices",
      crown_jewel: true,
      verified: false,
    },
  ],
};

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
