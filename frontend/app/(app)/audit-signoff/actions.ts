"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// The two things a reviewer does. Note what is absent: there is no "approve all". The reviewer is
// signing a document a third party relies on, and a bulk control would turn the one decision that
// cannot be automated into a single click — which is the false confidence this whole surface exists
// to prevent.
export async function decideFinding(
  target: string, key: string, verdict: string, severity: string, reason: string,
): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.decideAuditFinding(target, key, verdict, severity, reason);
    revalidatePath("/audit-signoff");
    return { ok: true };
  } catch (e) {
    // The server's refusals are written for the reviewer ("a reason is required to exclude or
    // reclassify a finding"), so they are surfaced verbatim rather than replaced with a generic one.
    return { ok: false, error: e instanceof Error ? e.message : "Could not record that decision." };
  }
}

export async function issueCertificate(
  target: string, notTested: string[],
): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.issueAuditCertificate(target, notTested);
    revalidatePath("/audit-signoff");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not issue the certificate." };
  }
}
