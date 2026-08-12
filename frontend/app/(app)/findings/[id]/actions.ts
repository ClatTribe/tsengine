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

export type LocalizeResult = { ok: boolean; answer?: string; error?: string };

// localizeFinding answers "where in the code does this actually live?" for one finding.
//
// Triggered rather than eager: it reads the connected repository's files to rank candidates, so running
// it on every finding-page load would make the page slow for the many findings that are not code issues
// at all. It is also the more honest shape — asking the engineer where something lives is an action a
// person takes, not a fact the page already knows.
export async function localizeFinding(findingID: string): Promise<LocalizeResult> {
  try {
    const r = await api.localize(findingID);
    return { ok: true, answer: r.answer };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Localization failed" };
  }
}
