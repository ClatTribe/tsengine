// The connector catalog the onboarding surface renders. The Go registry only exposes bare
// kind strings (Connectors.Kinds()); the labels, categories, and blurbs live here so the UI
// can group + describe them. Keep `kind` in lockstep with pkg/platform Conn* constants.

export type ConnectorCategory = "code" | "identity";

export interface ConnectorDef {
  kind: string;
  label: string;
  category: ConnectorCategory;
  blurb: string;
  /** What the agent does once connected — the value promise, shown on the card. */
  monitors: string;
}

export const CONNECTORS: ConnectorDef[] = [
  // Code & cloud — the security audience (repos, lockfiles, IaC, secrets).
  { kind: "github", label: "GitHub", category: "code", blurb: "Repos, lockfiles & secrets", monitors: "SAST, dependency CVEs, leaked secrets across your repos" },
  { kind: "gitlab", label: "GitLab", category: "code", blurb: "Repos, lockfiles & secrets", monitors: "SAST, dependency CVEs, leaked secrets across your projects" },
  { kind: "bitbucket", label: "Bitbucket", category: "code", blurb: "Repos, lockfiles & secrets", monitors: "SAST, dependency CVEs, leaked secrets across your Bitbucket repositories" },
  { kind: "aws", label: "AWS", category: "code", blurb: "Cloud posture (CIS, IAM)", monitors: "CIS misconfigurations, public exposure, over-broad IAM via a read-only role" },
  // Identity & email — the non-tech / compliance audience (MFA, OAuth grants, email auth).
  { kind: "gworkspace", label: "Google Workspace", category: "identity", blurb: "Identity, MFA & OAuth grants", monitors: "MFA gaps, risky OAuth apps, stale accounts, DMARC/SPF" },
  { kind: "m365", label: "Microsoft 365", category: "identity", blurb: "Identity, MFA & OAuth grants", monitors: "MFA gaps, risky OAuth apps, stale accounts, email auth" },
  { kind: "okta", label: "Okta", category: "identity", blurb: "Identity, MFA & admin roles", monitors: "MFA factors, admin-without-MFA, risky grants, stale users" },
];

export const CATEGORY_LABEL: Record<ConnectorCategory, string> = {
  code: "Code & cloud",
  identity: "Identity & email",
};

const BY_KIND = new Map(CONNECTORS.map((c) => [c.kind, c]));
export function connectorFor(kind: string): ConnectorDef | undefined {
  return BY_KIND.get(kind);
}

// Friendly label for a connection kind, falling back to the raw kind.
export function kindLabel(kind: string): string {
  return BY_KIND.get(kind)?.label ?? kind;
}

// Human label for an engine asset type (pkg/types.AssetType vocabulary).
export const ASSET_TYPE_LABEL: Record<string, string> = {
  repository: "Repository",
  container_image: "Container image",
  web_application: "Web app",
  api: "API",
  ip_address: "IP / host",
  domain: "Domain",
  cloud_account: "Cloud account",
  mobile_application: "Mobile app",
  workspace: "Workspace",
};
