import { Boxes, CircleAlert, ArrowUpRight, CheckCircle2 } from "lucide-react";
import { ProviderIcon } from "@/components/brand/provider-icon";
import { api } from "@/lib/api";
import type { Asset, Connection, Engagement } from "@/lib/types";
import { CONNECTORS, CATEGORY_LABEL, ASSET_TYPE_LABEL, kindLabel, type ConnectorCategory } from "@/lib/connectors";
import { AddTarget } from "@/components/assets/add-target";
import { SectionTitle, Empty, Tag } from "@/components/ui/primitives";
import { ScanNow } from "@/components/assets/scan-now";
import { DataTierSelect } from "@/components/assets/data-tier-select";
import { LoginFlowConfig } from "@/components/assets/login-flow-config";
import { AuthzTestConfig } from "@/components/assets/authz-test-config";
import { PageIntro } from "@/components/ui/page-intro";
import { timeAgo, cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

const STATUS_CLS: Record<string, string> = {
  active: "text-pulse border-pulse/30 bg-pulse/10",
  degraded: "text-medium border-medium/30 bg-medium/10",
  revoked: "text-critical border-critical/30 bg-critical/10",
};

export default async function AssetsPage({ searchParams }: { searchParams: Promise<{ connect_error?: string }> }) {
  const { connect_error } = await searchParams;
  const [connections, assets, engagements] = await Promise.all([api.connections(), api.assets(), api.engagements()]);

  // last-scanned per asset, from the engagement (monitoring-run) history
  const lastScan = new Map<string, string>();
  for (const e of engagements) {
    const t = e.completed_at || e.started_at;
    if (!t) continue;
    const prev = lastScan.get(e.asset_id);
    if (!prev || new Date(t) > new Date(prev)) lastScan.set(e.asset_id, t);
  }
  const connectedKinds = new Set(connections.map((c) => c.kind));

  return (
    <div className="space-y-8">
      <PageIntro
        icon={Boxes}
        title="Assets & connections"
        description="Everything we watch for you, in one place. Connect a system once — your code, cloud, identity provider, or SaaS — and the agent finds every asset inside it and keeps scanning them automatically."
        right={<ScanNow disabled={assets.length === 0} />}
      />

      {connect_error && (
        <div className="flex items-center gap-2 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
          <CircleAlert className="h-4 w-4" /> Couldn&apos;t start the {kindLabel(connect_error)} connection — it may not be configured on this deployment.
        </div>
      )}

      {/* Add a standalone target — the input the connectors don't cover (web/api/domain/ip/image) */}
      <section>
        <SectionTitle>Add a target</SectionTitle>
        <AddTarget />
      </section>

      {/* Connect a system */}
      <section>
        <SectionTitle>Connect a system</SectionTitle>
        <div className="space-y-5">
          {(["code", "identity"] as ConnectorCategory[]).map((cat) => (
            <div key={cat}>
              <div className="mb-2 text-[11px] uppercase tracking-wider text-faint">{CATEGORY_LABEL[cat]}</div>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {CONNECTORS.filter((c) => c.category === cat).map((c) => {
                  const connected = connectedKinds.has(c.kind);
                  return (
                    <a
                      key={c.kind}
                      href={`/connect/${c.kind}`}
                      className="group card flex flex-col gap-2 p-4 transition hover:border-accent/40 hover:bg-surface-2"
                    >
                      <div className="flex items-center gap-2.5">
                        <span className="grid h-8 w-8 place-items-center rounded-lg border border-border bg-surface-2 text-ink">
                          <ProviderIcon kind={c.kind} className="h-4 w-4" />
                        </span>
                        <span className="flex-1 text-sm font-medium">{c.label}</span>
                        {connected ? (
                          <span className="inline-flex items-center gap-1 text-[11px] text-pulse">
                            <CheckCircle2 className="h-3.5 w-3.5" /> connected
                          </span>
                        ) : (
                          <ArrowUpRight className="h-4 w-4 text-faint transition group-hover:text-accent" />
                        )}
                      </div>
                      <p className="text-xs leading-relaxed text-muted">{c.monitors}</p>
                      <p className="mt-1 text-[11px] leading-relaxed text-faint">{c.evidence}</p>
                      <span className="mt-auto text-[11px] text-accent opacity-0 transition group-hover:opacity-100">
                        {connected ? "Connect another →" : "Connect →"}
                      </span>
                    </a>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Connected systems */}
      <section>
        <SectionTitle>Connected systems</SectionTitle>
        {connections.length === 0 ? (
          <Empty>Nothing connected yet — pick a system above to start monitoring.</Empty>
        ) : (
          <div className="card divide-y divide-border p-0">
            {connections.map((c) => (
              <ConnectionRow key={c.id} conn={c} />
            ))}
          </div>
        )}
      </section>

      {/* Monitored assets */}
      <section>
        <SectionTitle action={<span className="text-[11px] text-faint">{assets.length} monitored</span>}>
          Monitored assets
        </SectionTitle>
        {assets.length > 0 && (
          <p className="mb-2 text-xs leading-relaxed text-muted">
            Tag each asset by how sensitive its data is. A finding on a{" "}
            <span className="text-critical">customer-data</span> asset is prioritized over the same
            finding on a low-sensitivity one — so triage starts where a breach would hurt most.
          </p>
        )}
        {assets.length === 0 ? (
          <Empty>No assets discovered yet. Connect a system and the agent enumerates what to watch.</Empty>
        ) : (
          <div className="card p-0">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
                  <th className="py-2.5 pl-5 pr-2 font-medium">Asset</th>
                  <th className="px-2 py-2.5 font-medium">Type</th>
                  <th className="px-2 py-2.5 font-medium">Data tier</th>
                  <th className="px-2 py-2.5 font-medium">Via</th>
                  <th className="py-2.5 pr-5 font-medium text-right">Last scanned</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a) => (
                  <AssetRow key={a.id} asset={a} connections={connections} last={lastScan.get(a.id)} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function ConnectionRow({ conn }: { conn: Connection }) {
  return (
    <div className="flex items-center gap-3 px-5 py-3">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-border bg-surface-2 text-ink">
        <ProviderIcon kind={conn.kind} className="h-4 w-4" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{kindLabel(conn.kind)}</div>
        <div className="mono truncate text-[11px] text-faint">{conn.account || conn.id}</div>
      </div>
      {conn.created_at && <span className="hidden text-xs text-faint sm:inline">connected {timeAgo(conn.created_at)}</span>}
      <span className={cn("inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-medium capitalize", STATUS_CLS[conn.status] ?? "text-muted border-border bg-surface-2")}>
        {conn.status}
      </span>
    </div>
  );
}

function AssetRow({ asset: a, connections, last }: { asset: Asset; connections: Connection[]; last?: string }) {
  const via = connections.find((c) => c.id === a.connection_id);
  return (
    <tr className="border-b border-border last:border-0 transition hover:bg-surface-2">
      <td className="max-w-0 py-2.5 pl-5 pr-2 align-middle">
        <div className="flex items-center gap-2">
          <Boxes className="h-3.5 w-3.5 shrink-0 text-faint" />
          <span className="mono truncate text-sm">{a.target}</span>
          {a.type === "web_application" && (
            <span className="shrink-0">
              <LoginFlowConfig assetId={a.id} configured={!!a.meta?.login_flow} />
            </span>
          )}
          {a.type === "api" && (
            <span className="shrink-0">
              <AuthzTestConfig assetId={a.id} configured={!!a.meta?.authz_test} />
            </span>
          )}
        </div>
      </td>
      <td className="px-2 py-2.5 align-middle">
        <Tag>{ASSET_TYPE_LABEL[a.type] ?? a.type}</Tag>
      </td>
      <td className="px-2 py-2.5 align-middle">
        <DataTierSelect assetId={a.id} tier={a.data_tier ?? 2} />
      </td>
      <td className="px-2 py-2.5 align-middle text-xs text-muted">{via ? kindLabel(via.kind) : "—"}</td>
      <td className="py-2.5 pr-5 align-middle text-right text-xs">
        {last ? <span className="text-pulse">{timeAgo(last)}</span> : <span className="text-faint">never</span>}
      </td>
    </tr>
  );
}
