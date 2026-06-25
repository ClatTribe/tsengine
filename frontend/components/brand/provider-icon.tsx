import type { LucideIcon } from "lucide-react";
import { Cloud, FileJson, Container, Webhook, Plug, ScrollText, Workflow } from "lucide-react";
import { BRAND_PATHS } from "@/lib/brand-paths";

// ProviderIcon — renders the real brand mark for a connector/integration (GitHub, Google, Slack, …)
// as a monochrome SVG in currentColor, so it stays crisp and works in both light and dark mode. This
// replaces the old generic lucide icons (every cloud was the same `Cloud`, every IdP a generic `Mail`).
// Accepts a connector kind (e.g. "gworkspace") or a display name (e.g. "Google Workspace").

const KIND_TO_BRAND: Record<string, string> = {
  github: "github",
  gitlab: "gitlab",
  bitbucket: "bitbucket",
  aws: "aws",
  gcp: "gcp",
  "google cloud": "gcp",
  azure: "azure",
  gworkspace: "google",
  "google workspace": "google",
  google: "google",
  gmail: "gmail",
  m365: "microsoft",
  "microsoft 365": "microsoft",
  microsoft: "microsoft",
  "microsoft teams": "microsoft",
  teams: "microsoft",
  okta: "okta",
  slack: "slack",
  jira: "jira",
  atlassian: "atlassian",
  zoom: "zoom",
  discord: "discord",
  pagerduty: "pagerduty",
  linear: "linear",
  docker: "docker",
  "docker hub": "docker",
  "github container registry": "github",
  kubernetes: "k8s",
};

// Kinds with no brand mark → a clean, DISTINCT lucide icon (never the old all-same Cloud).
const LUCIDE_FALLBACK: Record<string, LucideIcon> = {
  azuredevops: Workflow,
  "azure devops": Workflow,
  "amazon ecr": Container,
  "openapi / swagger": FileJson,
  openapi: FileJson,
  postman: FileJson,
  servicenow: ScrollText,
  webhooks: Webhook,
  webhook: Webhook,
  cloud: Cloud,
};

export function ProviderIcon({ kind, className }: { kind: string; className?: string }) {
  const key = kind.toLowerCase().trim();
  const brand = KIND_TO_BRAND[key];
  const path = brand ? BRAND_PATHS[brand] : undefined;
  if (path) {
    return (
      <svg viewBox="0 0 24 24" fill="currentColor" className={className} role="img" aria-label={kind}>
        <path d={path} />
      </svg>
    );
  }
  const Fallback = LUCIDE_FALLBACK[key] ?? Plug;
  return <Fallback className={className} aria-label={kind} />;
}
