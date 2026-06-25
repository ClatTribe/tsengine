"use client";

import {
  Bug, SealCheck, Pulse, Handshake, Fingerprint, Certificate, Cloud, Stack,
  Crosshair, ShieldCheck, LockKey, ScanSmiley, GitBranch, Key, Scales, Strategy,
  FileText, Bell, GitPullRequest, Package, Detective, Path, AppWindow, Robot, Lightning,
  PlugsConnected, Funnel, Wrench, Globe, Network, Buildings, Briefcase, Code, ClipboardText,
  CheckCircle, ArrowsLeftRight, DeviceMobile, Wallet, Eye, Lifebuoy, Gauge, Database,
  TreeStructure, Vault, ShieldStar, FileLock, Broadcast, UsersThree, ListChecks, Cpu,
  EnvelopeSimple, Power, Prohibit, Crown, ArrowsClockwise, Archive, CalendarX, Skull,
  FileCode, DownloadSimple, Terminal, Heart, TrendUp, UserGear, UserMinus, Clock, Sparkle, EyeSlash,
} from "@phosphor-icons/react";

// FeatureIcon — marketing/feature icons in Phosphor's DUOTONE weight (a solid primary layer + a
// tinted accent layer) so they read brand-forward and substantial, not thin "wireframes". Mapped by
// either a SEMANTIC name (detection, compliance, …) OR a lucide display-name (ShieldCheck, Cloud, …) —
// so a page converts with one find-replace: <Icon …/> → <FeatureIcon name={Icon.displayName} …/>.
// Monochrome currentColor → dark-mode safe.
const MAP: Record<string, typeof Bug> = {
  // semantic names (landing/product use these)
  detection: Bug, compliance: SealCheck, evidence: Certificate, monitoring: Pulse, hitl: Handshake,
  identity: Fingerprint, cloud: Cloud, "supply-chain": Stack, pentest: Crosshair, shield: ShieldCheck,
  lock: LockKey, scan: ScanSmiley, code: Code, key: Key, connect: PlugsConnected, detect: Bug,
  triage: Funnel, fix: Wrench, approve: CheckCircle, prove: SealCheck, web: Globe, api: ArrowsLeftRight,
  containers: Package, network: Network, recon: Detective, mobile: DeviceMobile, iac: TreeStructure,
  saas: AppWindow, data: Database, risk: Scales, strategy: Strategy, report: FileText, audit: ClipboardText,
  alert: Bell, pr: GitPullRequest, agent: Robot, fast: Lightning, path: Path, owner: Buildings,
  ops: Briefcase, devs: Code, team: UsersThree, wallet: Wallet, watch: Eye, support: Lifebuoy,
  speed: Gauge, vault: Vault, attest: ShieldStar, signed: FileLock, broadcast: Broadcast,
  checklist: ListChecks, engine: Cpu,

  // lucide display-name bridge → the closest duotone equivalent
  ShieldCheck, Cloud, KeyRound: Key, Fingerprint, Lock: LockKey, FileCheck2: SealCheck, EyeOff: EyeSlash,
  AppWindow, Bot: Robot, Mail: EnvelopeSimple, Radar: Broadcast, UserX: UserMinus, Webhook: Broadcast,
  Filter: Funnel, GitPullRequest, Power, ScanLine: ScanSmiley, ScrollText: FileText, UserCheck: Handshake,
  Wrench, Ban: Prohibit, ClipboardCheck: ClipboardText, Crosshair, Crown, FileText, RotateCw: ArrowsClockwise,
  Archive, Boxes: Stack, CalendarX, GitBranch, Scale: Scales, Skull, GitMerge: GitBranch, Layers: Stack,
  Spline: Path, BadgeCheck: SealCheck, Bug, ListChecks, CircleSlash: Prohibit, FileCode2: FileCode,
  GaugeCircle: Gauge, Import: DownloadSimple, Terminal, Heart, Sparkles: Sparkle, Target: Crosshair,
  Building2: Buildings, Clock, TrendingUp: TrendUp, UserCog: UserGear, CheckCircle2: CheckCircle,
  Globe, Code2: Code, Box: Package, Smartphone: DeviceMobile, Plug: PlugsConnected, ClipboardList: ClipboardText,
  Network,
};

export function FeatureIcon({ name, className }: { name?: string; className?: string }) {
  const Icon = (name && MAP[name]) || ShieldCheck;
  return <Icon weight="duotone" className={className} aria-hidden />;
}
