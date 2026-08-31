export type ConnectorCategory = "code" | "identity";

export interface ConnectorDef {
  kind: string;
  label: string;
  category: ConnectorCategory;
  blurb: string;
  monitors: string;
  evidence: string;
}

export const CONNECTORS: ConnectorDef[] = [
  // Code & cloud
  { kind: "github", label: "GitHub", category: "code", blurb: "Repos, lockfiles & secrets", monitors: "SAST, dependency CVEs, leaked secrets across your repos", evidence: "Evidence for secure-SDLC & change management — code review, vuln remediation (SOC 2 CC8.1 · ISO A.8.25–28)" },
  // { kind: "gitlab", label: "GitLab", category: "code", blurb: "Repos, lockfiles & secrets", monitors: "SAST, dependency CVEs, leaked secrets across your projects", evidence: "Evidence for secure-SDLC & change management — code review, vuln remediation (SOC 2 CC8.1 · ISO A.8.25–28)" },
  // { kind: "bitbucket", label: "Bitbucket", category: "code", blurb: "Repos, lockfiles & secrets", monitors: "SAST, dependency CVEs, leaked secrets across your Bitbucket repositories", evidence: "Evidence for secure-SDLC & change management — code review, vuln remediation (SOC 2 CC8.1 · ISO A.8.25–28)" },
  // { kind: "azuredevops", label: "Azure DevOps", category: "code", blurb: "Repos, lockfiles & secrets", monitors: "SAST, dependency CVEs, leaked secrets across your Azure DevOps repos", evidence: "Evidence for secure-SDLC & change management — code review, vuln remediation (SOC 2 CC8.1 · ISO A.8.25–28)" },
  { kind: "aws", label: "AWS", category: "code", blurb: "Cloud posture (CIS, IAM)", monitors: "CIS misconfigurations, public exposure, over-broad IAM via a read-only role", evidence: "Evidence for infrastructure access control & encryption — least-privilege, public-exposure (SOC 2 CC6.1/CC6.6 · CIS · ISO A.8.x)" },
  { kind: "gcp", label: "Google Cloud", category: "code", blurb: "Cloud posture (CIS, IAM)", monitors: "CIS misconfigurations, public exposure, over-broad IAM via a read-only Security Reviewer grant", evidence: "Evidence for infrastructure access control & encryption — least-privilege, public-exposure (SOC 2 CC6.1/CC6.6 · CIS · ISO A.8.x)" },
  // { kind: "azure", label: "Azure", category: "code", blurb: "Cloud posture (CIS, IAM)", monitors: "CIS misconfigurations, public exposure, over-broad RBAC via a read-only Reader grant", evidence: "Evidence for infrastructure access control & encryption — least-privilege, public-exposure (SOC 2 CC6.1/CC6.6 · CIS · ISO A.8.x)" },
  // Identity & email
  { kind: "gworkspace", label: "Google Workspace", category: "identity", blurb: "Identity, MFA & OAuth grants", monitors: "MFA gaps, risky OAuth apps, stale accounts, DMARC/SPF", evidence: "Evidence for logical access & MFA — identity, MFA enforcement, deprovisioning (SOC 2 CC6.1–6.3 · ISO A.5.15–18)" },
  // { kind: "m365", label: "Microsoft 365", category: "identity", blurb: "Identity, MFA & OAuth grants", monitors: "MFA gaps, risky OAuth apps, stale accounts, email auth", evidence: "Evidence for logical access & MFA — identity, MFA enforcement, deprovisioning (SOC 2 CC6.1–6.3 · ISO A.5.15–18)" },
  { kind: "okta", label: "Okta", category: "identity", blurb: "Identity, MFA & admin roles", monitors: "MFA factors, admin-without-MFA, risky grants, stale users", evidence: "Evidence for logical access & MFA — identity, MFA enforcement, deprovisioning (SOC 2 CC6.1–6.3 · ISO A.5.15–18)" },
];

export const CATEGORY_LABEL: Record<ConnectorCategory, string> = {
  code: "Code & cloud",
  identity: "Identity & email",
};

const BY_KIND = new Map(CONNECTORS.map((c) => [c.kind, c]));
export function connectorFor(kind: string): ConnectorDef | undefined {
  return BY_KIND.get(kind);
}

export function kindLabel(kind: string): string {
  return BY_KIND.get(kind)?.label ?? kind;
}

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