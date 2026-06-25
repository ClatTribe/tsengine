"use client";

import {
  Bug, SealCheck, Pulse, Handshake, Fingerprint, Certificate, Cloud, Stack,
  Crosshair, ShieldCheck, LockKey, ScanSmiley, GitBranch, Key, Scales, Strategy,
  FileText, Bell, GitPullRequest, Package, Detective, Path, AppWindow, Robot, Lightning,
  PlugsConnected, Funnel, Wrench, Globe, Network, Buildings, Briefcase, Code, ClipboardText,
  CheckCircle, ArrowsLeftRight, DeviceMobile, Wallet, Eye, Lifebuoy, Gauge, Database,
  TreeStructure, Vault, ShieldStar, FileLock, Broadcast, UsersThree, ListChecks, Cpu,
} from "@phosphor-icons/react";

// FeatureIcon — marketing/feature icons in Phosphor's DUOTONE weight (a solid primary layer + a
// tinted accent layer) so they read brand-forward and substantial, not thin "wireframes". Mapped by a
// semantic name so callers don't import icon components; monochrome currentColor → dark-mode safe.
const MAP: Record<string, typeof Bug> = {
  // core capabilities
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
  code: Code,
  key: Key,
  // workflow steps
  connect: PlugsConnected,
  detect: Bug,
  triage: Funnel,
  fix: Wrench,
  approve: CheckCircle,
  prove: SealCheck,
  // surfaces
  web: Globe,
  api: ArrowsLeftRight,
  containers: Package,
  network: Network,
  recon: Detective,
  mobile: DeviceMobile,
  iac: TreeStructure,
  saas: AppWindow,
  data: Database,
  // governance / ops / personas
  risk: Scales,
  strategy: Strategy,
  report: FileText,
  audit: ClipboardText,
  alert: Bell,
  pr: GitPullRequest,
  agent: Robot,
  fast: Lightning,
  path: Path,
  owner: Buildings,
  ops: Briefcase,
  devs: Code,
  team: UsersThree,
  wallet: Wallet,
  watch: Eye,
  support: Lifebuoy,
  speed: Gauge,
  vault: Vault,
  attest: ShieldStar,
  signed: FileLock,
  broadcast: Broadcast,
  checklist: ListChecks,
  engine: Cpu,
};

export function FeatureIcon({ name, className }: { name: string; className?: string }) {
  const Icon = MAP[name] ?? ShieldCheck;
  return <Icon weight="duotone" className={className} aria-hidden />;
}
