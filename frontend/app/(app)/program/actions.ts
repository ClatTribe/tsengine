"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Seed the standard policy set as drafts. Idempotent server-side.
export async function seedProgram(): Promise<void> {
  await api.seedProgram();
  revalidatePath("/program");
}

// Publish a policy — the HITL act. The owner defaults to the authenticated user (the person taking
// accountability), never trusted from the client; the API records it into the ledger.
export async function publishPolicy(id: string): Promise<void> {
  const me = await api.me();
  await api.publishPolicy(id, me?.email ?? "");
  revalidatePath("/program");
}

// Acknowledge a published policy — the acking user is the authenticated session user.
export async function ackPolicy(id: string): Promise<void> {
  const me = await api.me();
  await api.ackPolicy(id, me?.email ?? "");
  revalidatePath("/program");
}
