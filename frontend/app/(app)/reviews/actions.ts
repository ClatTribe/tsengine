"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Open an expert-review request on a finding directly from the Reviews page — the founder escalates
// a judgment call to a human (the MSP/managed HITL) without first navigating to the finding detail.
export async function submitReview(findingId: string, note: string) {
  if (!findingId) return;
  await api.requestReview("finding", findingId, note);
  revalidatePath("/reviews");
}
