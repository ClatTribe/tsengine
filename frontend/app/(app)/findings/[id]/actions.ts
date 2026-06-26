"use server";

import { api } from "@/lib/api";

export type AutofixResult = { ok: boolean; fix?: string; error?: string };

// Runs the AI autofix agent for one finding → an LLM-generated, grounded code patch. Slow (an LLM call),
// so the caller shows a loading state. A named human still reviews + merges the patch (HITL).
export async function getAutofix(id: string): Promise<AutofixResult> {
  try {
    const r = await api.autofix(id);
    return { ok: true, fix: r.fix };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not generate a fix" };
  }
}
