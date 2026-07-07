"use server";

import { api } from "@/lib/api";

export type FixPlan = { ok: boolean; plan?: string; gapCount?: number; error?: string };

// Runs the vCISO remediation-guidance agent for a framework's control gaps. Slow (an LLM call), so the
// caller shows a loading state.
export async function getFixGuidance(framework: string): Promise<FixPlan> {
  try {
    const r = await api.complianceRemediation(framework);
    return { ok: true, plan: r.plan, gapCount: r.gap_count };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not generate guidance" };
  }
}

// Captures the framework's current posture onto the continuous-evidence timeline (an on-demand
// snapshot; the monitoring loop also captures automatically). Returns whether a point was recorded.
export async function captureEvidence(framework: string): Promise<{ ok: boolean; captured?: boolean; error?: string }> {
  try {
    const r = await api.captureEvidence(framework);
    return { ok: true, captured: r.captured };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not capture evidence" };
  }
}

export type Roadmap = { ok: boolean; roadmap?: string; coveragePct?: number; error?: string };

// Runs the vCISO advisor — a prioritized audit-readiness roadmap over coverage + gaps + readiness. Slow.
export async function getAdvisorRoadmap(framework: string): Promise<Roadmap> {
  try {
    const r = await api.complianceAdvisor(framework);
    return { ok: true, roadmap: r.roadmap, coveragePct: r.coverage?.automated_coverage_pct };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Could not generate the roadmap" };
  }
}
