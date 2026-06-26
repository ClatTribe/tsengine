"use server";

import { api } from "@/lib/api";

export type FixPlan = { ok: boolean; plan?: string; gapCount?: number; error?: string };

// Runs the vCISO remediation-guidance agent for a framework's control gaps. Slow (an LLM call), so the
// caller shows a loading state.
export async function getFixGuidance(framework: string): Promise<FixPlan> {
  try {
    const r = await api.complianceRemediation(framework);
    return { ok: true, plan: r.plan, gapCount: r.gap_count };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not generate guidance" };
  }
}
