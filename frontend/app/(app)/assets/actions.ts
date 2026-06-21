"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Triggers a re-scan of every monitored asset (the same RescanTenant path the scheduler +
// webhooks drive). The platform runs it as a background job and returns immediately — so
// the button reports "started" rather than blocking on a possibly-minutes-long scan. (If
// the platform scans synchronously, it returns the asset count instead.)
export async function rescanAll(): Promise<{ scanned?: number; queued?: boolean }> {
  const res = await api.rescan();
  revalidatePath("/assets");
  revalidatePath("/dashboard"); // Overview risk + activity may shift after a fresh scan
  if (typeof res.assets_scanned === "number") return { scanned: res.assets_scanned };
  return { queued: true };
}

// Sets an asset's customer-data-sensitivity tier (1 = customer data, 2 = standard, 3 = low).
// The tier feeds the platform's risk-adjusted ranking so a finding on a customer-data repo is
// prioritized over the same finding on a low-sensitivity one (the Synthesia repo-tiering idea).
export async function setAssetDataTier(id: string, tier: number): Promise<void> {
  await api.setAssetDataTier(id, tier);
  revalidatePath("/assets");
  revalidatePath("/issues"); // risk-adjusted ordering may shift
}
