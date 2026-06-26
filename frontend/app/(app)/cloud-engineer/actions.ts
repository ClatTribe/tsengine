"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Triggers an AI Cloud Engineer investigation from the UI (the in-product "Run" the page previously only
// described via API/CLI). The user pastes a cloud inventory snapshot (a CloudQuery/Cartography export) +
// optional prowler findings; the agent reasons over the graph and its proven attack paths flow into the
// page, issues, and the vCISO risk desk. Validates the JSON client-side intent here, surfaces the server's
// honest LLM-gating error (no model configured → a clear message), and revalidates on success.
export async function runCloudInvestigation(
  inventoryText: string,
  prowlerText: string,
): Promise<{ ok: boolean; error?: string; pathsFound?: number; risksProposed?: number; summary?: string }> {
  let inventory: unknown;
  try {
    inventory = JSON.parse(inventoryText);
  } catch {
    return { ok: false, error: "The inventory isn't valid JSON. Paste a CloudQuery/Cartography inventory export." };
  }
  let prowler: unknown[] = [];
  if (prowlerText.trim() !== "") {
    try {
      const p = JSON.parse(prowlerText);
      if (!Array.isArray(p)) return { ok: false, error: "Prowler findings must be a JSON array." };
      prowler = p;
    } catch {
      return { ok: false, error: "The prowler findings aren't valid JSON (expected an array)." };
    }
  }
  try {
    const res = await api.runCloudInvestigation(inventory, prowler);
    revalidatePath("/cloud-engineer");
    revalidatePath("/issues");
    revalidatePath("/risks");
    return { ok: true, pathsFound: res.paths_found, risksProposed: res.risks_proposed, summary: res.summary };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "The investigation failed." };
  }
}
