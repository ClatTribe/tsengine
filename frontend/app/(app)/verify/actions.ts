"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Reinstating is a human overruling the filter, so it returns the failure reason rather than
// throwing it away — an override that silently did nothing would be the worst possible outcome on
// a screen whose entire purpose is trust.
export async function reinstateAction(findingId: string, reason: string): Promise<{ error?: string }> {
  try {
    await api.reinstateFinding(findingId, reason);
  } catch (e) {
    return { error: e instanceof Error ? e.message : "Could not reinstate that finding." };
  } finally {
    revalidatePath("/verify");
    revalidatePath("/findings");
  }
  return {};
}
