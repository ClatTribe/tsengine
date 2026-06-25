"use client";

import {
  Bug, SealCheck, Pulse, Handshake, Fingerprint, Certificate, Cloud, Stack,
  Crosshair, ShieldCheck, LockKey, ScanSmiley, GitBranch, Key, Scales, Strategy,
  FileText, Bell, GitPullRequest, Package, Detective, Path, AppWindow, Robot, Lightning,
} from "@phosphor-icons/react";

// FeatureIcon — the marketing/feature icons rendered in Phosphor's DUOTONE weight (a solid primary
// layer + a tinted accent layer), so they read as brand-forward and substantial instead of thin
// outline "wireframes". Mapped by a semantic name so callers don't import icon components. Monochrome
// currentColor (inherits the accent chip) → works in light and dark mode.
const MAP: Record<string, typeof Bug> = {
  detection: Bug,
  compliance: SealCheck,
  evidence: Certificate,
  monitoring: Pulse,
  hitl: Handshake,
  identity: Fingerprint,
  cloud: Cloud,
  "supply-chain": Stack,
  pentest: Crosshair,
  shield: ShieldCheck,
  lock: LockKey,
  scan: ScanSmiley,
  code: GitBranch,
  key: Key,
  risk: Scales,
  strategy: Strategy,
  report: FileText,
  alert: Bell,
  pr: GitPullRequest,
  containers: Package,
  recon: Detective,
  path: Path,
  saas: AppWindow,
  agent: Robot,
  fast: Lightning,
};

export function FeatureIcon({ name, className }: { name: string; className?: string }) {
  const Icon = MAP[name] ?? ShieldCheck;
  return <Icon weight="duotone" className={className} aria-hidden />;
}
