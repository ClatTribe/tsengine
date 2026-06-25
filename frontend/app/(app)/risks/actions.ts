"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Seed candidate risks from the tenant's current high+ findings (grounded; the agent only proposes).
export async function seedRisks(): Promise<void> {
  await api.seedRisks();
  revalidatePath("/risks");
}

// The human-in-the-loop treatment decision: a named owner accepts/mitigates/transfers/avoids the
// risk with a rationale. The decision is signed into the ledger server-side. The owner defaults to
// the authenticated user's email if the form leaves it blank — never trusted from an anonymous client.
export async function decideRisk(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  const treatment = String(formData.get("treatment") ?? "");
  const rationale = String(formData.get("rationale") ?? "");
  let owner = String(formData.get("owner") ?? "").trim();
  if (!owner) {
    const me = await api.me();
    owner = me?.email ?? "";
  }
  await api.decideRisk(id, { treatment, owner, rationale });
  revalidatePath("/risks");
}
