"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// The three things a person can do to a checklist row, and nothing else.
//
// Note what is missing: there is no "mark as done". A measured row is answered by a scanner, and
// letting someone tick it by hand would turn evidence into an opinion — the server refuses that, and
// not offering it here means nobody has to discover the refusal.

/** Records the company's funding stage — the one onboarding question. */
export async function setStage(stage: string): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.setReadinessStage(stage);
    revalidatePath("/readiness");
    revalidatePath("/dashboard");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not save that." };
  }
}

/** Hands a gap row's findings to the proposer. Everything it produces waits at the approval desk. */
export async function closeGap(id: string): Promise<{ ok: boolean; detail?: string; error?: string }> {
  try {
    const res = await api.closeReadinessGap(id);
    revalidatePath("/readiness");
    revalidatePath("/inbox");
    return { ok: true, detail: res.detail };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not propose a fix." };
  }
}

/** Records a named human's answer to a practice no scan can see. Both answers are kept. */
export async function attest(
  id: string,
  inPlace: boolean,
  by: string,
): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.attestReadiness(id, inPlace, by);
    revalidatePath("/readiness");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not record that." };
  }
}
