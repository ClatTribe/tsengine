"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

export async function addNote(text: string): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.addAgentNote(text);
    revalidatePath("/memory");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "could not save the note" };
  }
}

export async function removeNote(id: string): Promise<void> {
  await api.deleteAgentNote(id);
  revalidatePath("/memory");
}
