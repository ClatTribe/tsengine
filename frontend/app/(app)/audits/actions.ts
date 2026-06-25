"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Open an audit engagement — seeds the controls to attest from the tenant's posture for the framework.
export async function createAudit(formData: FormData): Promise<void> {
  await api.createAudit({
    framework: String(formData.get("framework") ?? ""),
    audit_type: String(formData.get("audit_type") ?? "type_i"),
    auditor_name: String(formData.get("auditor_name") ?? ""),
    auditor_firm: String(formData.get("auditor_firm") ?? ""),
    auditor_email: String(formData.get("auditor_email") ?? ""),
  });
  revalidatePath("/audits");
}

// The HITL: the external auditor's per-control verdict. attested_by names the auditor (it is not the
// app user — the auditor is an independent human; the form carries their name, pre-filled from the
// engagement). Signed into the ledger server-side.
export async function attestControl(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  await api.attestControl(id, {
    control_id: String(formData.get("control_id") ?? ""),
    verdict: String(formData.get("verdict") ?? ""),
    note: String(formData.get("note") ?? ""),
    attested_by: String(formData.get("attested_by") ?? ""),
  });
  revalidatePath("/audits");
}

// Mark the engagement issued — refused server-side unless a named auditor + every control attested.
export async function issueAudit(formData: FormData): Promise<void> {
  await api.issueAudit(String(formData.get("id") ?? ""));
  revalidatePath("/audits");
}
