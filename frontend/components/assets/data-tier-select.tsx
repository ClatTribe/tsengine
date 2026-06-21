"use client";

import { useTransition } from "react";
import { ShieldAlert, Shield, ShieldOff, Loader2 } from "lucide-react";
import { setAssetDataTier } from "@/app/(app)/assets/actions";
import { cn } from "@/lib/utils";

// The three customer-data-sensitivity tiers, mirroring pkg/platform/datatier.go. Tier 1 raises
// the risk-adjusted ranking of an asset's findings; tier 3 lowers it.
const TIERS = [
  { value: 1, label: "Customer data", icon: ShieldAlert, cls: "text-critical border-critical/30 bg-critical/10" },
  { value: 2, label: "Standard", icon: Shield, cls: "text-muted border-border bg-surface-2" },
  { value: 3, label: "Low sensitivity", icon: ShieldOff, cls: "text-faint border-border bg-surface-2" },
] as const;

// DataTierSelect lets an owner classify how sensitive an asset's data is. The choice feeds the
// platform's risk-adjusted prioritization (crossdetect.RiskWeight) — a finding on a
// customer-data repo outranks the same finding on a low-sensitivity one (the Synthesia
// repo-tiering control). Engine detection is unchanged; this only reorders triage.
export function DataTierSelect({ assetId, tier }: { assetId: string; tier: number }) {
  const [pending, start] = useTransition();
  const current = TIERS.find((t) => t.value === tier) ?? TIERS[1];
  const Icon = current.icon;

  function pick(next: number) {
    if (next === tier || pending) return;
    start(() => setAssetDataTier(assetId, next));
  }

  return (
    <div className="inline-flex items-center gap-1.5">
      <span className={cn("inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium", current.cls)}>
        {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Icon className="h-3 w-3" />}
        {current.label}
      </span>
      <select
        aria-label="Data sensitivity tier"
        value={tier}
        disabled={pending}
        onChange={(e) => pick(Number(e.target.value))}
        className="rounded-md border border-border bg-surface-2 px-1 py-0.5 text-[11px] text-muted outline-none transition hover:border-accent/40 disabled:opacity-50"
      >
        {TIERS.map((t) => (
          <option key={t.value} value={t.value}>
            {t.label}
          </option>
        ))}
      </select>
    </div>
  );
}
