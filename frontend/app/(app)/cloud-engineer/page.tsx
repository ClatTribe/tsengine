import Link from "next/link";
import { Cloud, ShieldAlert, Workflow, Plug, ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { SeverityBadge, Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { ConfidencePill } from "@/components/findings/confidence-pill";
import { RunInvestigation } from "@/components/cloud/run-investigation";

export const dynamic = "force-dynamic";

// The AI Cloud Security Engineer (cloudagent) surface: the proven, cross-resource attack paths the
// agent confirmed over a cloud account's inventory — each grounded in the graph tools, each with a
// verified remediation. Read-only view; an investigation is triggered by POST /v1/cloud/investigate
// (LLM-gated). Mirrors how /pentest surfaces the productized agent.
export default async function CloudEngineerPage() {
  const { total, enabled, paths } = await api.cloudInvestigation();
  const order = ["critical", "high", "medium", "low", "info"];
  const sorted = [...paths].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));

  return (
    <div className="space-y-8">
      <PageIntro
        icon={Cloud}
        title="AI Cloud Security Engineer"
        description="An autonomous agent investigates a cloud account by querying its graph — resolving effective permissions, tracing reachability, and measuring blast radius — to find the attack paths an external attacker could actually use to reach a crown jewel. It tells real, exploitable paths apart from config-bad-but-inert noise, and every path it records is backed by a tool result with a verified fix. Results flow into your issues, attack paths, and compliance posture."
      />

      <PageTabs tabs={[{ href: "/attack-paths", label: "Attack paths" }, { href: "/cloud-engineer", label: "Cloud investigation" }]} />

      <RunInvestigation />

      {!enabled ? (
        <div className="rounded-xl border border-border bg-surface p-6">
          <div className="flex items-center gap-2 text-sm font-semibold text-ink">
            <Cloud className="h-4 w-4 text-accent" /> Turn on the AI Cloud Engineer
          </div>
          <p className="mt-1.5 max-w-2xl text-sm text-muted">
            Connect a cloud account and the agent investigates it for you — mapping effective permissions,
            reachability, and blast radius to surface the attack paths that actually reach a crown jewel.
          </p>
          <Link
            href="/assets"
            className="mt-4 inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover"
          >
            <Plug className="h-4 w-4" /> Connect a cloud account <ArrowRight className="h-4 w-4" />
          </Link>
          <p className="mt-4 max-w-2xl text-xs leading-relaxed text-faint">
            For operators: the agent also needs an AI key — set <code className="mono">LLM_API_KEY</code> (cloud)
            or <code className="mono">LLM_BASE_URL=http://localhost:11434/v1</code> +{" "}
            <code className="mono">LLM_MODEL=qwen2.5</code> (local Ollama), then restart. Advanced: trigger
            directly via <code className="mono">POST /v1/cloud/investigate</code> or{" "}
            <code className="mono">tsengine cloud-investigate</code>.
          </p>
        </div>
      ) : total === 0 ? (
        <Empty>
          <div className="space-y-4">
            <p>
              No attack paths recorded yet. Connect a cloud account and the agent will investigate it — its
              proven, remediated paths appear here and flow into your issues + compliance posture.
            </p>
            <Link
              href="/assets"
              className="inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover"
            >
              <Plug className="h-4 w-4" /> Connect a cloud account
            </Link>
            <p className="text-xs text-faint">
              Advanced: <code className="mono text-xs">POST /v1/cloud/investigate</code> with a cloud inventory
              snapshot, or run <code className="mono text-xs">tsengine cloud-investigate</code>.
            </p>
          </div>
        </Empty>
      ) : (
        <section className="card divide-y divide-border">
          {sorted.map((f) => (
            <div key={f.id} className="flex items-start gap-3 px-5 py-3.5">
              <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                <Workflow className="h-4 w-4" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-ink">{f.title}</span>
                  <SeverityBadge severity={f.severity} />
                  <ConfidencePill verification={f.verification_status} confidence={f.confidence} />
                </div>
                {f.description && <p className="mt-1 whitespace-pre-line text-sm leading-relaxed text-muted">{f.description}</p>}
                {f.endpoint && <div className="mono mt-1 truncate text-[11px] text-faint">{f.endpoint}</div>}
              </div>
            </div>
          ))}
        </section>
      )}

      <p className="flex items-center gap-1.5 text-xs text-faint">
        <ShieldAlert className="h-3.5 w-3.5" /> The agent reasons over the cloud graph; every recorded path
        cites a deterministic tool result (no LLM-asserted findings). Mutations stay human-gated.
      </p>
    </div>
  );
}
