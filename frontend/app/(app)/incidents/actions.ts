"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Acknowledge an open incident — records that a human took ownership, which stops the timed
// auto-escalation. The acting user comes from the authenticated session (api.me), never the client.
export async function acknowledgeIncident(id: string): Promise<void> {
  const me = await api.me();
  await api.ackIncident(id, me?.email);
  revalidatePath("/incidents");
}
