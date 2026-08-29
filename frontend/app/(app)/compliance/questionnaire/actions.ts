"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Record a named human's answer to a questionnaire question no scan can reach.
//
// The API refuses this outright for an evidenced question — those are checked on every scan, so a
// typed answer would replace an observation with an opinion in a document a buyer relies on. The
// refusal lives there rather than here because there is more than one caller.
export async function attestQuestion(id: string, inPlace: boolean, by: string, note: string): Promise<void> {
  await api.attestQuestion(id, inPlace, by, note);
  revalidatePath("/compliance/questionnaire");
  // The buyer-facing document is generated from the same answers, so it changes too.
  revalidatePath("/compliance");
}
