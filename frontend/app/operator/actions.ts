"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
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
