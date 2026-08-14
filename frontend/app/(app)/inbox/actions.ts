"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// The approval decision goes through the SAME gated desk the Go API/Slack use — tier rules
// + the signed ledger still apply. This Server Action is just a typed client of that gate.
export async function decideAction(id: string, approve: boolean) {
  await api.decide(id, approve, "console-operator");
  revalidatePath("/inbox");
  revalidatePath("/dashboard"); // refresh the Overview "needs you" + the sidebar badge
}

// requestChangesAction is the third verdict — send it back rather than kill it.
//
// With only approve/reject, spotting one wrong line means destroying a proposal that was mostly
// right, which trains rubber-stamping. This routes through the SAME gated desk: the action stays
// open, nothing is applied, and the note is signed into the ledger like any other decision.
export async function requestChangesAction(id: string, feedback: string) {
  const note = feedback.trim();
  // Mirrors the server-side rule rather than relying on it: "change this" with no "this" is
  // indistinguishable from a rejection and leaves the agent nothing to act on.
  if (!note) return { error: "Say what should change — an empty note reads as a rejection." };
  try {
    await api.requestChanges(id, note, "console-operator");
  } catch (e) {
    return { error: e instanceof Error ? e.message : "Could not send it back." };
  }
  revalidatePath("/inbox");
  revalidatePath("/dashboard");
  return {};
}
