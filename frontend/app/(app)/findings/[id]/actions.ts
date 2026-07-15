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

export type FixPRResult = {
  ok: boolean;
  patched?: boolean;
  reason?: string;
  filesChanged?: string[];
  repo?: string;
  error?: string;
};

// Opens a real fix PR for one finding: the engineer reads the ACTUAL source, patches it, and the patch
// is queued as a gated action — approving it is what pushes the commit and opens the PR. Slow (an LLM
// call over real source), so the caller shows a loading state.
export async function openFixPR(id: string): Promise<FixPRResult> {
  try {
    const r = await api.fixPR(id);
    return { ok: true, patched: r.patched, reason: r.reason, filesChanged: r.files_changed, repo: r.repo };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not open a fix PR" };
  }
}
