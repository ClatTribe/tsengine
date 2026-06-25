"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Triggers a re-scan of every monitored asset (the same RescanTenant path the scheduler +
// webhooks drive). The platform runs it as a background job and returns immediately — so
// the button reports "started" rather than blocking on a possibly-minutes-long scan. (If
// the platform scans synchronously, it returns the asset count instead.)
export async function rescanAll(): Promise<{ scanned?: number; queued?: boolean }> {
  const res = await api.rescan();
  revalidatePath("/assets");
  revalidatePath("/dashboard"); // Overview risk + activity may shift after a fresh scan
  if (typeof res.assets_scanned === "number") return { scanned: res.assets_scanned };
  return { queued: true };
}

// Adds a standalone scan target — the founder's website / API / domain / IP / container image,
// the input the connectors (code/cloud/identity) don't cover. The user must attest they're
// authorized to scan it; the server validates + SSRF-screens the target (no private/reserved hosts).
// On success the new asset flows into the same scan loop as connector-discovered assets.
export async function addTarget(
  type: string,
  target: string,
  authorized: boolean,
): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.addAsset(type, target, authorized);
    revalidatePath("/assets");
    revalidatePath("/dashboard");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not add the target" };
  }
}

// Sets an asset's customer-data-sensitivity tier (1 = customer data, 2 = standard, 3 = low).
// The tier feeds the platform's risk-adjusted ranking so a finding on a customer-data repo is
// prioritized over the same finding on a low-sensitivity one (the Synthesia repo-tiering idea).
export async function setAssetDataTier(id: string, tier: number): Promise<void> {
  await api.setAssetDataTier(id, tier);
  revalidatePath("/assets");
  revalidatePath("/issues"); // risk-adjusted ordering may shift
}

// Configures authenticated scanning for a web asset from the common form-login inputs: a single
// login POST + a validate URL + a success marker. The scanner replays this and confirms the
// session each scan so it never silently scans logged-out (the FN guard). Credentials are sealed
// server-side. Returns an error string on failure (e.g. no secret vault configured).
export async function setLoginFlow(id: string, f: {
  loginUrl: string;
  userField: string;
  username: string;
  passField: string;
  password: string;
  validateUrl: string;
  successMarker: string;
}): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.setLoginFlow(id, {
      type: "form",
      steps: [{ method: "POST", url: f.loginUrl, fields: { [f.userField || "username"]: f.username, [f.passField || "password"]: f.password } }],
      validate_url: f.validateUrl,
      success_marker: f.successMarker,
    });
    revalidatePath("/assets");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "failed to save" };
  }
}

// Configures the BOLA/BFLA authorization test for an api asset: two identities (a victim that
// owns an object, an attacker that's a different lower-privilege principal) + the object-bearing
// operations to test. The engine replays the victim's request as the attacker and flags only a
// proven bypass (verified, no-FP). Auth headers are sealed server-side. Returns an error string
// on failure (e.g. no secret vault configured).
export async function setAuthzTest(id: string, c: {
  victimAuth: string;
  attackerAuth: string;
  operations: { method: string; url: string; class: string; marker: string }[];
}): Promise<{ ok: boolean; error?: string }> {
  try {
    await api.setAuthzTest(id, {
      victim: { name: "victim", headers: { Authorization: c.victimAuth } },
      attacker: { name: "attacker", headers: { Authorization: c.attackerAuth } },
      operations: c.operations
        .filter((o) => o.url.trim() !== "")
        .map((o) => ({ method: o.method, url: o.url, class: o.class, marker: o.marker })),
    });
    revalidatePath("/assets");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "failed to save" };
  }
}
