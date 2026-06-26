"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";
import type { ComplianceProfile } from "@/lib/types";

export type SaveResult = { ok: boolean; error?: string };

export async function saveComplianceScope(targetFrameworks: string[], profile: ComplianceProfile): Promise<SaveResult> {
  try {
    await api.setComplianceScope({ target_frameworks: targetFrameworks, compliance_profile: profile });
    revalidatePath("/compliance");
    revalidatePath("/compliance/scope");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not save the scope" };
  }
}
