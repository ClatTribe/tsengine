"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

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
