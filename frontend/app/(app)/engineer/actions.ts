"use server";

import { api } from "@/lib/api";

export type AskResult = { ok: boolean; query: string; answer?: string; error?: string };

// askEstate answers a question from the tenant's OWN findings and assets.
//
// It hits the same endpoint the AI Security Engineer's search_estate tool uses, so the answer here and
// the answer the agent reasons over are the same text. No model runs — this is a query over stored
// findings — which is why it returns instantly and cannot embellish. An empty answer means the estate
// genuinely has no match, not that a model failed to recall one.
export async function askEstate(q: string): Promise<AskResult> {
  const query = q.trim();
  if (!query) return { ok: false, query, error: "Type a question first." };
  try {
    const r = await api.ask(query);
    return { ok: true, query, answer: r.answer };
  } catch (e) {
    return { ok: false, query, error: e instanceof Error ? e.message : "Search failed" };
  }
}
