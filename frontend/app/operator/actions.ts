"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { apiBase } from "@/lib/auth";
import { OP_TOKEN_COOKIE, operatorCookieOptions } from "@/lib/operator";

// operatorLogin verifies email+password against the Go API and, on success, stores the operator token
// in its own httpOnly cookie (separate from the tenant session). Returns an error string on failure.
export async function operatorLogin(_prev: string | null, formData: FormData): Promise<string | null> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const res = await fetch(apiBase() + "/v1/operator/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
    cache: "no-store",
  });
  if (!res.ok) return "Invalid email or password.";
  const data = (await res.json()) as { token?: string };
  if (!data.token) return "Login failed.";
  const jar = await cookies();
  jar.set(OP_TOKEN_COOKIE, data.token, operatorCookieOptions());
  redirect("/operator");
}

// operatorDecideRisk makes a risk treatment decision ON BEHALF of an assigned client, from the
// cross-tenant console. The Go API enforces that the operator is a practitioner of record on that
// client (else 403) and records the decision with the operator's name + roster capacity, signed into
// the ledger. Returns an error string on failure, else null (the page revalidates).
export async function operatorDecideRisk(_prev: string | null, formData: FormData): Promise<string | null> {
  const tenant = String(formData.get("tenant") ?? "");
  const risk = String(formData.get("risk") ?? "");
  const treatment = String(formData.get("treatment") ?? "");
  const rationale = String(formData.get("rationale") ?? "").trim();
  if (!tenant || !risk || !treatment) return "Pick a treatment.";
  const tok = (await cookies()).get(OP_TOKEN_COOKIE)?.value;
  if (!tok) return "Your session expired — sign in again.";
  const res = await fetch(apiBase() + `/v1/operator/tenants/${tenant}/risks/${risk}/decision`, {
    method: "POST",
    headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
    body: JSON.stringify({ treatment, rationale }),
    cache: "no-store",
  });
  if (res.status === 403) return "You are not a practitioner of record for this client.";
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    return body.error || "Could not record the decision.";
  }
  revalidatePath("/operator");
  return null;
}

export async function operatorLogout(): Promise<void> {
  const jar = await cookies();
  const tok = jar.get(OP_TOKEN_COOKIE)?.value;
  if (tok) {
    await fetch(apiBase() + "/v1/operator/logout", {
      method: "POST",
      headers: { Authorization: `Bearer ${tok}` },
      cache: "no-store",
    }).catch(() => {});
  }
  jar.delete(OP_TOKEN_COOKIE);
  redirect("/operator/login");
}
