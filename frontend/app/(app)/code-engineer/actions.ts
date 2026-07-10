"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

export type CodeIssue = {
  id: string;
  finding_id: string;
  title: string;
  severity?: string;
  exploitable: boolean;
  rationale?: string;
  evidence?: string[];
  blast_radius?: string;
  fix_location?: string;
  fix?: string;
};

export type CodeInvestigationResult = {
  ok: boolean;
  error?: string;
  summary?: string;
  issues?: CodeIssue[];
  assessed?: number;
  confirmed?: number;
  risksProposed?: number;
};

// Runs the AI Code Engineer over posted code findings + repo source. The agent opens the source, traces the
// tainted value to its sink (or a secret to its usage), and returns a GROUNDED assessment — exploitable vs
// contained, blast radius, and the right-layer fix. Confirmed-exploitable ones persist as verified findings
// server-side (flowing into issues/grc/incidents); the response also carries the full assessment inline.
export async function runCodeInvestigation(
  repo: string,
  findingsText: string,
  sourceText: string,
): Promise<CodeInvestigationResult> {
  let findings: unknown[];
  try {
    const f = JSON.parse(findingsText);
    if (!Array.isArray(f)) return { ok: false, error: "Findings must be a JSON array of code findings." };
    findings = f;
  } catch {
    return { ok: false, error: "The findings aren't valid JSON (expected an array of code findings)." };
  }
  if (findings.length === 0) return { ok: false, error: "Add at least one code finding to assess." };

  let source: Record<string, string> = {};
  if (sourceText.trim() !== "") {
    try {
      const s = JSON.parse(sourceText);
      if (typeof s !== "object" || s === null || Array.isArray(s)) {
        return { ok: false, error: "Source must be a JSON object mapping file path → file content." };
      }
      source = s as Record<string, string>;
    } catch {
      return { ok: false, error: "The source isn't valid JSON (expected {\"path\": \"content\"})." };
    }
  }

  try {
    const res = await api.runCodeInvestigation(repo.trim(), findings, source);
    revalidatePath("/code-engineer");
    revalidatePath("/issues");
    return { ok: true, summary: res.summary, issues: res.issues, assessed: res.findings_assessed, confirmed: res.confirmed_exploitable, risksProposed: res.risks_proposed };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "The code investigation failed." };
  }
}
