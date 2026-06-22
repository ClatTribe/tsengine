"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Engage/disengage the global kill-switch (agentic-SMB spec OM-3 / TS-5). When engaged the
// platform takes no autonomous agent action — no scans, no remediation writes — until a
// human disengages it. Revalidates the surfaces that show the halted state.
export async function setKillSwitch(halted: boolean): Promise<{ halted: boolean }> {
  const t = await api.killSwitch(halted);
  revalidatePath("/settings");
  revalidatePath("/dashboard");
  return { halted: !!t.agents_halted };
}

// Quarantine/restore ONE connection (WRD-4 per-agent kill-switch). Returns the new status.
export async function setQuarantine(id: string, quarantined: boolean): Promise<{ status: string }> {
  const c = await api.quarantineConnection(id, quarantined);
  revalidatePath("/settings");
  return { status: c.status };
}

// Set a cloud connection's per-tenant remediation write role (Bucket B). The role/SA is the
// customer's own — used at HITL-approved remediation time. Returns the stored config.
export async function setCloudRemediation(
  id: string,
  cfg: { enabled: boolean; role_arn?: string; region?: string; impersonate_sa?: string },
): Promise<{ config?: Record<string, string> }> {
  const c = await api.setCloudRemediation(id, cfg);
  revalidatePath("/settings");
  return { config: c.config };
}

// Set the tenant's LLM provider/model and (optionally) seal a new API key. An empty key keeps
// the existing one. The key is sealed server-side and never returned.
export async function setLLMConfig(
  provider: string,
  model: string,
  apiKey: string,
): Promise<{ provider: string; model: string; has_key: boolean }> {
  const r = await api.setLLMConfig(provider, model, apiKey);
  revalidatePath("/settings");
  return r;
}

// Set the repository PR-review-bot policy: enable inline review + a merge-gating check-run, and
// the severity floor that fails the check ("off" = comment-only). The live GitHub post stays
// gated on a connected GitHub App with the PR scope.
export async function setPRBotPolicy(
  enabled: boolean,
  blockSeverity: string,
): Promise<{ enabled: boolean; block_severity: string }> {
  const r = await api.setPRBotSettings(enabled, blockSeverity);
  revalidatePath("/settings");
  return { enabled: r.enabled, block_severity: r.block_severity };
}
