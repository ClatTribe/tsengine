"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { apiBase } from "@/lib/auth";
import { OP_MFA_COOKIE, OP_TOKEN_COOKIE, operatorCookieOptions } from "@/lib/operator";

// LoginState drives the operator sign-in form: an error, and whether the code step is showing.
export type LoginState = { error?: string; needCode?: boolean } | null;

// operatorLogin verifies email+password against the Go API and, on success, stores the operator token
// in its own httpOnly cookie (separate from the tenant session). When the operator has two-factor on,
// the API returns a challenge instead; it is held in its own httpOnly cookie and the form asks for the
// code. Nothing is signed in until the code is.
export async function operatorLogin(prev: LoginState, formData: FormData): Promise<LoginState> {
  if (prev?.needCode) return operatorVerify(formData);
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const res = await fetch(apiBase() + "/v1/operator/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
    cache: "no-store",
  });
  if (!res.ok) return { error: "Invalid email or password." };
  const data = (await res.json()) as { token?: string; two_factor_required?: boolean; challenge?: string };
  const jar = await cookies();
  if (data.two_factor_required && data.challenge) {
    jar.set(OP_MFA_COOKIE, data.challenge, { ...operatorCookieOptions(), maxAge: 5 * 60 });
    return { needCode: true };
  }
  if (!data.token) return { error: "Login failed." };
  jar.set(OP_TOKEN_COOKIE, data.token, operatorCookieOptions());
  redirect("/operator");
}

// operatorVerify redeems the challenge with a code (or a recovery code: anything that is not six digits).
async function operatorVerify(formData: FormData): Promise<LoginState> {
  const raw = String(formData.get("code") ?? "").trim();
  const jar = await cookies();
  const challenge = jar.get(OP_MFA_COOKIE)?.value;
  if (!challenge) return { error: "This sign-in has expired — enter your email and password again." };
  const isCode = /^\d{6}$/.test(raw.replace(/\s/g, ""));
  const res = await fetch(apiBase() + "/v1/operator/2fa/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(isCode ? { challenge, code: raw } : { challenge, recovery_code: raw }),
    cache: "no-store",
  });
  const data = (await res.json().catch(() => ({}))) as { token?: string; error?: string; code?: string };
  if (!res.ok) {
    // Expired or burned: back to the password step, and say why.
    if (data.code === "two_factor_expired" || data.code === "two_factor_locked") {
      jar.delete(OP_MFA_COOKIE);
      return { error: data.error ?? "Sign in again." };
    }
    return { needCode: true, error: data.error ?? "That code is not right." };
  }
  if (!data.token) return { error: "Login failed." };
  jar.delete(OP_MFA_COOKIE);
  jar.set(OP_TOKEN_COOKIE, data.token, operatorCookieOptions());
  redirect("/operator");
}

// Operator two-factor management. Each returns the server's refusal as text.
type Result<T> = ({ ok: true } & T) | { ok: false; error: string };
async function opPost<T>(path: string, body: unknown): Promise<Result<T>> {
  const tok = (await cookies()).get(OP_TOKEN_COOKIE)?.value;
  if (!tok) return { ok: false, error: "Your session expired — sign in again." };
  const res = await fetch(apiBase() + path, {
    method: "POST",
    headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  const data = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) return { ok: false, error: data.error ?? `HTTP ${res.status}` };
  revalidatePath("/operator");
  return { ok: true, ...data };
}
export async function operatorStartTwoFactor(password: string) {
  return opPost<{ secret: string; uri: string }>("/v1/operator/2fa/setup", { password });
}
export async function operatorConfirmTwoFactor(code: string) {
  return opPost<{ recovery_codes: string[]; warning?: string }>("/v1/operator/2fa/enable", { code });
}
export async function operatorDisableTwoFactor(b: { password: string; code?: string; recovery_code?: string }) {
  return opPost<object>("/v1/operator/2fa/disable", b);
}
export async function operatorReplaceRecoveryCodes(b: { password: string; code?: string; recovery_code?: string }) {
  return opPost<{ recovery_codes: string[] }>("/v1/operator/2fa/recovery-codes", b);
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

// operatorPublishPolicy publishes a client's draft policy ON BEHALF, from the cross-tenant console.
// Roster-gated server-side (403 if not a practitioner of record); recorded with the operator's name +
// capacity and signed into the ledger.
export async function operatorPublishPolicy(_prev: string | null, formData: FormData): Promise<string | null> {
  const tenant = String(formData.get("tenant") ?? "");
  const policy = String(formData.get("policy") ?? "");
  if (!tenant || !policy) return "Missing policy.";
  const tok = (await cookies()).get(OP_TOKEN_COOKIE)?.value;
  if (!tok) return "Your session expired — sign in again.";
  const res = await fetch(apiBase() + `/v1/operator/tenants/${tenant}/policies/${policy}/publish`, {
    method: "POST",
    headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
    body: "{}",
    cache: "no-store",
  });
  if (res.status === 403) return "You are not a practitioner of record for this client.";
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    return body.error || "Could not publish the policy.";
  }
  revalidatePath("/operator");
  return null;
}

// operatorSignoffPentest signs off a client's pentest report ON BEHALF — the named-accountability act.
// Roster-gated server-side (403 if not a practitioner of record); recorded with the operator's name,
// role + capacity, signed into the ledger and stamped onto the report.
export async function operatorSignoffPentest(_prev: string | null, formData: FormData): Promise<string | null> {
  const tenant = String(formData.get("tenant") ?? "");
  const engagement = String(formData.get("engagement") ?? "");
  const role = String(formData.get("role") ?? "").trim();
  const statement = String(formData.get("statement") ?? "").trim();
  if (!tenant || !engagement) return "Missing report.";
  const tok = (await cookies()).get(OP_TOKEN_COOKIE)?.value;
  if (!tok) return "Your session expired — sign in again.";
  const res = await fetch(apiBase() + `/v1/operator/tenants/${tenant}/pentests/${engagement}/signoff`, {
    method: "POST",
    headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
    body: JSON.stringify({ role, statement }),
    cache: "no-store",
  });
  if (res.status === 403) return "You are not a practitioner of record for this client.";
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    return body.error || "Could not sign off the report.";
  }
  revalidatePath("/operator");
  return null;
}

// operatorAttestControl records the auditor verdict on one control of a client's audit ON BEHALF — the
// independent-attestation act. Roster-gated server-side (403 if not a practitioner of record);
// recorded with the operator's name + capacity and signed into the ledger.
export async function operatorAttestControl(_prev: string | null, formData: FormData): Promise<string | null> {
  const tenant = String(formData.get("tenant") ?? "");
  const audit = String(formData.get("audit") ?? "");
  const control = String(formData.get("control_id") ?? "");
  const verdict = String(formData.get("verdict") ?? "");
  const note = String(formData.get("note") ?? "").trim();
  if (!tenant || !audit || !control || !verdict) return "Pick a control and a verdict.";
  const tok = (await cookies()).get(OP_TOKEN_COOKIE)?.value;
  if (!tok) return "Your session expired — sign in again.";
  const res = await fetch(apiBase() + `/v1/operator/tenants/${tenant}/audits/${audit}/attest`, {
    method: "POST",
    headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
    body: JSON.stringify({ control_id: control, verdict, note }),
    cache: "no-store",
  });
  if (res.status === 403) return "You are not a practitioner of record for this client.";
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    return body.error || "Could not record the attestation.";
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
