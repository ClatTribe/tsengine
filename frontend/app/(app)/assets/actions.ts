"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Triggers an immediate re-scan of every monitored asset (the same RescanTenant path the
// scheduler + webhooks drive). Returns the count so the button can confirm.
export async function rescanAll(): Promise<{ scanned: number }> {
  const { assets_scanned } = await api.rescan();
  revalidatePath("/assets");
  revalidatePath("/"); // Overview risk + activity may shift after a fresh scan
  return { scanned: assets_scanned };
}
