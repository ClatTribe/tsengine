"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Runs a LIVE keyless OSINT scan (Certificate Transparency via crt.sh) over the tenant's domains — no
// API key, no sandbox. Returns the discovery counts; the new findings flow into issues + compliance.
export async function runOsintScan(): Promise<{
  ok: boolean;
  hosts?: number;
  findings?: number;
  pivoted?: number;
  error?: string;
}> {
  try {
    const r = await api.osintScan();
    revalidatePath("/osint");
    revalidatePath("/issues");
    revalidatePath("/assets");
    return { ok: true, hosts: r.hosts_discovered, findings: r.findings_detected, pivoted: r.assets_pivoted };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Scan failed" };
  }
}
