"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// The approval decision goes through the SAME gated desk the Go API/Slack use — tier rules
// + the signed ledger still apply. This Server Action is just a typed client of that gate.
export async function decideAction(id: string, approve: boolean) {
  await api.decide(id, approve, "console-operator");
  revalidatePath("/inbox");
  revalidatePath("/"); // refresh the Overview "needs you" + the sidebar badge
}
