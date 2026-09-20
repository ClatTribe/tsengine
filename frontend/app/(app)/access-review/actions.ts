"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// The one thing a person can do here: answer, by name, whether an account still needs its access.
//
// Note what is NOT here. There is no "revoke access" action, because recording a revoke verdict does
// not revoke anything — the removal is a change, and every change in this product goes through the
// approval desk (§18.2 inv. 3). Offering a button that appeared to act would be the worst possible
// place to blur that: a reviewer would close the campaign believing the accounts were gone.
export async function decideAccess(formData: FormData): Promise<void> {
  const subject = String(formData.get("subject") ?? "");
  const decision = String(formData.get("decision") ?? "") as "keep" | "revoke";
  const note = String(formData.get("note") ?? "");
  let by = String(formData.get("by") ?? "").trim();
  if (!by) {
    // The reviewer's name is what makes this evidence rather than a log line, so it is never left
    // empty — it falls back to the authenticated user, never to an anonymous string.
    const me = await api.me();
    by = me?.email ?? "";
  }
  await api.decideAccessReview(subject, decision, by, note);
  revalidatePath("/access-review");
  revalidatePath("/compliance");
}
