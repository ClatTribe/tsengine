import { ScanSearch, CheckCircle2, CircleDashed } from "lucide-react";
import { api } from "@/lib/api";
import { Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { timeAgo } from "@/lib/utils";

export const dynamic = "force-dynamic";

const TYPE_LABEL: Record<string, string> = {
  web_application: "Web app",
  api: "API",
  repository: "Repository",
  container_image: "Container image",
  ip_address: "IP / host",
  domain: "Domain",
  cloud_account: "Cloud account",
  mobile_application: "Mobile app",
  workspace: "Identity / workspace",
};

export default async function CoveragePage() {
  const cov = await api.coverage();

  return (
    <div className="space-y-5">
      <PageIntro
        icon={ScanSearch}
        title="Test coverage"
        description="Exactly what was tested on each asset — the tools every scan runs, when it last ran, and which of them surfaced something. No black box: a clean tool ran, it just found nothing."
      />

      <PageTabs tabs={[{ href: "/coverage", label: "Test coverage" }, { href: "/posture", label: "Asset posture" }]} />

      {cov.total_assets > 0 && (
        <div className="card flex items-center gap-3 px-4 py-3 text-sm">
          <ScanSearch className="h-4 w-4 shrink-0 text-accent" />
          <span className="text-muted">
            <span className="font-medium text-ink">{cov.scanned_assets} of {cov.total_assets}</span> assets have been
            scanned. Each card below shows precisely what ran — so you never have to take coverage on trust.
          </span>
        </div>
      )}

      {cov.assets.length === 0 ? (
        <Empty>No assets yet — connect a system or add a target to see exactly what gets tested.</Empty>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {cov.assets.map((a) => {
            const found = new Set(a.tools_with_findings);
            return (
              <div key={a.asset_id} className="card p-5">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="mono truncate text-sm text-ink">{a.target}</div>
                    <div className="mt-0.5 text-xs text-faint">{TYPE_LABEL[a.type] ?? a.type}</div>
                  </div>
                  {a.scanned ? (
                    <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-pulse/30 bg-pulse/10 px-2 py-0.5 text-[11px] font-medium text-pulse">
                      <CheckCircle2 className="h-3 w-3" /> Scanned {a.last_scanned_at ? timeAgo(a.last_scanned_at) : ""}
                    </span>
                  ) : (
                    <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium text-muted">
                      <CircleDashed className="h-3 w-3" /> Not yet scanned
                    </span>
                  )}
                </div>

                <div className="mt-3.5 text-[11px] font-medium uppercase tracking-wider text-faint">
                  {a.scanned ? "Tools run on every scan" : "Tools this scan will run"}
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {a.runs_tools.length === 0 ? (
                    <span className="text-xs text-muted">Posture checks (no OSS scanners for this asset type)</span>
                  ) : (
                    a.runs_tools.map((t) => {
                      const hit = found.has(t);
                      return (
                        <span
                          key={t}
                          className={
                            "mono inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] " +
                            (hit
                              ? "border-high/30 bg-high/10 text-high"
                              : a.scanned
                                ? "border-border bg-surface text-muted"
                                : "border-border bg-surface text-faint")
                          }
                          title={hit ? "surfaced a finding" : a.scanned ? "ran, found nothing" : "will run on next scan"}
                        >
                          {hit && <span className="h-1.5 w-1.5 rounded-full bg-high" />}
                          {t}
                        </span>
                      );
                    })
                  )}
                </div>

                {a.scanned && (
                  <div className="mt-3 text-xs text-muted">
                    {a.findings_count > 0 ? (
                      <>
                        <span className="font-medium text-ink">{a.findings_count}</span> finding{a.findings_count === 1 ? "" : "s"} from{" "}
                        <span className="font-medium text-ink">{a.tools_with_findings.length}</span> tool
                        {a.tools_with_findings.length === 1 ? "" : "s"}; the rest ran clean.
                      </>
                    ) : (
                      <>All tools ran and found nothing — a clean result, not a skipped scan.</>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
