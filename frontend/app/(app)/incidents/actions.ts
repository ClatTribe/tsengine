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

// Close an incident with the reason. The closer is the signed-in person (the server reads the session);
// an EVENT incident (a login, a spray, a trail stopped) can only be closed this way — a later scan not
// seeing the event again is not evidence anyone dealt with it.
export async function resolveIncident(id: string, reason: string): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.resolveIncident(id, reason);
    revalidatePath("/incidents");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "could not close the incident" };
  }
}
