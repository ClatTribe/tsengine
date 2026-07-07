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

// lastTriage returns the tenant's most-recent PERSISTED whole-estate triage as a Brief, so the console
// shows the last analysis on load (survives navigation) instead of a bare button. null → never run yet.
export async function lastTriage(): Promise<(Brief & { created_at: string }) | null> {
  const { analyses } = await api.aiAnalyses("triage");
  if (analyses.length === 0) return null;
  const a = analyses[0];
  return {
    ok: true,
    created_at: a.created_at,
    model: a.model,
    summary: { executive_summary: a.summary, recommendations: a.recommends, methodology: a.methodology },
    reports: (a.reports ?? []).map((r, i) => ({
      id: `${a.id}-${i}`,
      title: r.title,
      severity: r.severity ?? "info",
      description: r.body,
    })),
  };
}
