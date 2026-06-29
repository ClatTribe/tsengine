"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

export type InvestigateResult =
  | { ok: true; data: Awaited<ReturnType<typeof api.investigateIssue>> }
  | { ok: false; error: string };

// AI per-issue Investigate — the agentic verb. Returns the grounded cross-surface chain + blast radius
// always; the root-cause/fix narrative when AI is enabled. Never throws to the client.
export async function investigateIssue(key: string): Promise<InvestigateResult> {
  try {
    return { ok: true, data: await api.investigateIssue(key) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not investigate this issue" };
  }
}

// Suppress a unified issue (false-positive / accepted-risk). Routes through the
// ledger-recorded /v1/issues/ignore path; the issue drops off the active list.
export async function ignoreIssue(key: string, reason: string, note: string) {
  await api.ignoreIssue(key, reason, note);
  revalidatePath("/issues");
  revalidatePath("/dashboard");
}

// Restore a previously-suppressed issue to the active list.
export async function unignoreIssue(key: string) {
  await api.unignoreIssue(key);
  revalidatePath("/issues");
  revalidatePath("/dashboard");
}

// Add a custom exclusion rule (path/package/rule-id/cve glob). Matching findings
// drop out before they're unified, so the noise never becomes an issue.
export async function addExclusion(field: string, pattern: string, reason: string) {
  await api.addExclusion(field, pattern, reason);
  revalidatePath("/issues");
  revalidatePath("/dashboard");
}

// Remove an exclusion rule (its findings reappear).
export async function deleteExclusion(id: string) {
  await api.deleteExclusion(id);
  revalidatePath("/issues");
  revalidatePath("/dashboard");
}
