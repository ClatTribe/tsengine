"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

export type PrepareResult = { ok: true; detail: string } | { ok: false; error: string };

// Prepare one plan step: the server proposes a fix per real asset and routes each to the approval
// desk. Nothing is applied here. The server's own detail line is returned verbatim, because it
// checks what is ACTUALLY true of those actions (waiting vs already delivered) rather than assuming.
export async function prepareFixStep(key: string): Promise<PrepareResult> {
  try {
    const r = await api.prepareFixStep(key);
    revalidatePath("/fixes");
    revalidatePath("/inbox");
    return { ok: true, detail: r.detail };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not prepare these fixes" };
  }
}
