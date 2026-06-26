"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";
import type { CustomControl } from "@/lib/types";

export type AddResult = { ok: boolean; error?: string };

// Create a custom framework. Each control line is "Name | ref1, ref2" where a ref is cwe:CWE-89,
// rule:secrets, or a built-in control like soc2:CC6.1. Parsing is forgiving; the backend validates.
export async function addCustomFramework(formData: FormData): Promise<AddResult> {
  const name = String(formData.get("name") ?? "").trim();
  const description = String(formData.get("description") ?? "").trim();
  const raw = String(formData.get("controls") ?? "").trim();
  if (!name) return { ok: false, error: "Name is required" };
  const controls: CustomControl[] = raw
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line, i) => {
      const [label, refs] = line.split("|");
      return {
        id: `c${i + 1}`,
        name: (label ?? "").trim(),
        maps_to: (refs ?? "")
          .split(",")
          .map((r) => r.trim())
          .filter(Boolean),
      };
    });
  if (controls.length === 0) return { ok: false, error: "Add at least one control" };
  try {
    await api.addCustomFramework({ name, description, controls });
    revalidatePath("/compliance/custom");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not create the framework" };
  }
}

export async function deleteCustomFramework(id: string): Promise<void> {
  await api.deleteCustomFramework(id);
  revalidatePath("/compliance/custom");
}
