"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Requests a human-expert review of a finding (the AI + human escalation). Routes through
// the same ledger-signed /v1/reviews path the API/desk use.
export async function submitReview(subjectId: string, note: string) {
  await api.requestReview("finding", subjectId, note);
  revalidatePath(`/findings/${subjectId}`);
}
