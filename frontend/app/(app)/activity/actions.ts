"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

export type ObjectiveResult = { ok: true } | { ok: false; error: string };

// Declare the exposure target the trend is graded against. The server forces declared:true —
// reaching this call IS the declaration.
export async function setExposureObjective(windowDays: number, netPerWindow: number, minConfirmedFixed: number): Promise<ObjectiveResult> {
  try {
    await api.setExposureObjective({ window_days: windowDays, net_per_window: netPerWindow, min_confirmed_fixed: minConfirmedFixed });
    revalidatePath("/activity");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not save the objective" };
  }
}

// Allow or withdraw earned autonomy for one kind of fix. The server refuses an allow the record has not
// earned, and refuses anyone but the owner; this passes its words through rather than inventing its own.
export async function setAutonomy(cls: string, remediationType: string, allow: boolean): Promise<ObjectiveResult> {
  try {
    await api.setAutonomy({ class: cls, remediation_type: remediationType, allow });
    revalidatePath("/activity");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not change earned autonomy" };
  }
}
