"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Confirming you have read a module. There is no subject parameter, and that is the point: the
// server takes the person from the session, because "delivered" asserts that we showed the content
// to THAT person and a session is the only evidence of it. A subject the client could set would let
// anyone record that a colleague had read something.
export async function confirmRead(moduleID: string): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.completeTraining(moduleID);
    revalidatePath("/training");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not record that." };
  }
}

// Recording training somebody completed elsewhere. This always lands as the ATTESTED tier — it is a
// second-hand claim and the server will not let this path mint the stronger one.
export async function recordExternal(formData: FormData): Promise<void> {
  await api.recordTraining(
    String(formData.get("subject") ?? ""),
    String(formData.get("module_id") ?? ""),
    String(formData.get("provider") ?? ""),
    String(formData.get("on") ?? ""),
    String(formData.get("note") ?? ""),
  );
  revalidatePath("/training");
}
