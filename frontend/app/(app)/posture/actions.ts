"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";
import type { DatabaseScanResult } from "@/lib/types";

// Scan a Postgres the customer names, once, from a connection string they paste.
//
// The DSN is passed through to the API and never stored — not by us, not in the form. It is the one
// integration in this segment's stack that needs no OAuth app and no connector build, so it is worth
// a real control rather than an endpoint documented in an empty state.
export async function scanDatabase(dsn: string, sampleValues: boolean): Promise<DatabaseScanResult> {
  const res = await api.scanDatabase(dsn, sampleValues);
  // New findings land in the shared store, so the surfaces that read it are now stale.
  revalidatePath("/posture");
  revalidatePath("/issues");
  revalidatePath("/dashboard");
  return res;
}

// Adding or updating one vendor. Note there is no "assess" action: the server re-assesses the whole
// register on every write, because vendor risk is a property of the PORTFOLIO — assessing only the
// edited row would leave findings standing for vendors that have since been fixed.
export async function saveVendor(formData: FormData): Promise<void> {
  const certs = String(formData.get("certifications") ?? "")
    .split(",")
    .map((c) => c.trim())
    .filter(Boolean);
  await api.putVendor({
    id: String(formData.get("id") ?? "") || undefined,
    name: String(formData.get("name") ?? ""),
    owner: String(formData.get("owner") ?? ""),
    category: String(formData.get("category") ?? ""),
    data_access: (String(formData.get("data_access") ?? "") || undefined) as never,
    subprocessor: formData.get("subprocessor") === "on",
    handles_card_data: formData.get("handles_card_data") === "on",
    has_dpa: formData.get("has_dpa") === "on",
    certifications: certs,
    criticality: String(formData.get("criticality") ?? ""),
    last_assessed: String(formData.get("last_assessed") ?? ""),
  });
  revalidatePath("/posture");
}

export async function removeVendor(id: string): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.deleteVendor(id);
    revalidatePath("/posture");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not remove that vendor." };
  }
}
