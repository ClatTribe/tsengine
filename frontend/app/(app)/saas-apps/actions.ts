"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Escalate a risky third-party SaaS app or non-human identity to the expert-review desk.
// The founder can't (and shouldn't) decide alone whether an over-permissioned app is acceptable —
// this routes it to a human expert (the MSP/managed HITL), and the request shows up on /reviews.
export async function flagForReview(subject: "saas_app" | "identity", name: string, note: string) {
  await api.requestReview(subject, name, note);
  revalidatePath("/saas-apps");
  revalidatePath("/reviews");
}
