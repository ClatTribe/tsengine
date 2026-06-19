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
