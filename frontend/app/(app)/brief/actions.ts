"use server";

import { api } from "@/lib/api";

export type Brief = {
  ok: boolean;
  summary?: { executive_summary?: string; methodology?: string; recommendations?: string } | null;
  reports?: { id: string; title: string; severity: string; description?: string; endpoint?: string }[];
  model?: string;
  error?: string;
};

// Runs the L2 Lead/translator over the tenant's findings → the plain-English consultant brief. Slow
// (an LLM agent loop), so the caller shows a loading state.
export async function generateBrief(): Promise<Brief> {
  try {
    const r = await api.l2Translate();
    return { ok: true, summary: r.summary, reports: r.reports ?? [], model: r.model };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Translation failed" };
  }
}
