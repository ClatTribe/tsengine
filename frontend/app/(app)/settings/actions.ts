"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";
import type {
  BoardDigestSettings, Branding, BrandingSettings, DeviceSyncResult, EscalationPolicy, HRISSettings, HRISSyncResult, MDMSettings, SLAPolicy, TrustCenterConfig,
} from "@/lib/types";

// Engage/disengage the global kill-switch (agentic-SMB spec OM-3 / TS-5). When engaged the
// platform takes no autonomous agent action — no scans, no remediation writes — until a
// human disengages it. Revalidates the surfaces that show the halted state.
export async function setKillSwitch(halted: boolean): Promise<{ halted: boolean }> {
  const t = await api.killSwitch(halted);
  revalidatePath("/settings");
  revalidatePath("/dashboard");
  return { halted: !!t.agents_halted };
}

// Quarantine/restore ONE connection (WRD-4 per-agent kill-switch). Returns the new status.
export async function setQuarantine(id: string, quarantined: boolean): Promise<{ status: string }> {
  const c = await api.quarantineConnection(id, quarantined);
  revalidatePath("/settings");
  return { status: c.status };
}

// Run the live GitHub-org SaaS-posture sync via the onboarded GitHub token. Returns the number
// of posture findings stored (they appear in Issues/Incidents).
export async function syncGitHubPosture(): Promise<{ findings: number }> {
  const r = await api.syncGitHubPosture();
  revalidatePath("/settings");
  revalidatePath("/issues");
  return { findings: r.findings_detected };
}

// Live Okta configuration posture. Returns the findings stored AND how many settings the token
// could not read — the second number is what stops zero findings reading as a hardened org.
export async function syncOktaPosture(): Promise<{ findings: number; unread: number }> {
  const r = await api.syncOktaPosture();
  revalidatePath("/settings");
  revalidatePath("/issues");
  return { findings: r.count, unread: Object.keys(r.unread ?? {}).length };
}

// Live CloudTrail poll. Returns the threats stored AND the spans a truncated read left unexamined —
// the second is what stops zero threats reading as a quiet account.
export async function syncCloudEvents(): Promise<{ records: number; findings: number; unread: number }> {
  const r = await api.syncCloudEvents();
  revalidatePath("/settings");
  revalidatePath("/issues");
  revalidatePath("/incidents");
  return { records: r.records, findings: r.findings.length, unread: Object.keys(r.unread ?? {}).length };
}

// Set (or clear) the tenant's device-management source (Bucket B). Credentials are sealed
// server-side and never returned; we get back the redacted view.
export async function setMDM(cfg: {
  provider: string; base_url: string; api_token: string; client_id: string; client_secret: string;
}): Promise<MDMSettings> {
  const r = await api.setMDMSettings(cfg);
  revalidatePath("/settings");
  return r;
}

// Read the fleet from the configured MDM now and assess it. The result carries what the sync could
// NOT assess (provider limits, unread devices) beside the count, so the caller can show both.
export async function syncDevices(): Promise<DeviceSyncResult> {
  const r = await api.syncDevices();
  revalidatePath("/settings");
  revalidatePath("/issues");
  revalidatePath("/posture");
  return r;
}

// Set (or clear) the tenant's HR-system source (Bucket B). Credentials sealed, never returned.
export async function setHRIS(cfg: { provider: string; api_key: string; account_token: string }): Promise<HRISSettings> {
  const r = await api.setHRISSettings(cfg);
  revalidatePath("/settings");
  return r;
}

// Fetch the roster now and join it against every connected identity provider.
export async function syncHRIS(): Promise<HRISSyncResult> {
  const r = await api.syncHRIS();
  revalidatePath("/settings");
  revalidatePath("/issues");
  revalidatePath("/posture");
  return r;
}

// Set the tenant's incident escalation matrix (severity-tiered routing to alert channels).
export async function setEscalation(pol: EscalationPolicy): Promise<EscalationPolicy> {
  const r = await api.setEscalationSettings(pol);
  revalidatePath("/settings");
  return r;
}

// Set the tenant's remediation SLA policy (per-severity ack/resolve hour targets).
export async function setSLA(pol: SLAPolicy): Promise<SLAPolicy> {
  const r = await api.setSLASettings(pol);
  revalidatePath("/settings");
  revalidatePath("/incidents");
  return r;
}

export async function setBoardDigest(b: { enabled: boolean; cadence?: string; recipients?: string[] }): Promise<BoardDigestSettings> {
  const r = await api.setBoardDigest(b);
  revalidatePath("/settings");
  return r;
}

export async function sendBoardDigestNow(): Promise<BoardDigestSettings> {
  const r = await api.sendBoardDigest();
  revalidatePath("/settings");
  return r;
}

// Schedule a maintenance / change-freeze window (suppresses alerting while active).
export async function addMaintenanceWindow(w: { name: string; starts_at: string; ends_at: string; reason?: string }): Promise<void> {
  await api.addMaintenanceWindow(w);
  revalidatePath("/settings");
  revalidatePath("/incidents");
}

// Cancel a maintenance window.
export async function deleteMaintenanceWindow(id: string): Promise<void> {
  await api.deleteMaintenanceWindow(id);
  revalidatePath("/settings");
  revalidatePath("/incidents");
}

// Add / remove an on-call escalation contact (the roster the escalation matrix names).
export async function addContact(c: { name: string; role?: string; email?: string; phone?: string; slack_id?: string; order: number }): Promise<void> {
  await api.addContact(c);
  revalidatePath("/settings");
}
export async function deleteContact(id: string): Promise<void> {
  await api.deleteContact(id);
  revalidatePath("/settings");
}

// Set (or clear) the tenant's own Jira ticketing destination (Bucket B). The API token is sealed
// server-side and never returned; we get back base/email/project + whether a token is set.
export async function setJira(
  cfg: { base_url: string; email: string; project: string; api_token: string },
): Promise<{ base_url: string; email: string; project: string; has_token: boolean }> {
  const r = await api.setJiraSettings(cfg);
  revalidatePath("/settings");
  return r;
}

// Set (or clear) the tenant's own Slack incident webhook (Bucket B). The URL is a bearer
// capability, so it is sealed server-side and never returned; we get back only presence.
export async function setSlackWebhook(slackWebhook: string): Promise<{ has_slack_webhook: boolean }> {
  const r = await api.setNotifySettings(slackWebhook);
  revalidatePath("/settings");
  return { has_slack_webhook: r.has_slack_webhook };
}

// Set a cloud connection's per-tenant remediation write role (Bucket B). The role/SA is the
// customer's own — used at HITL-approved remediation time. Returns the stored config.
export async function setCloudRemediation(
  id: string,
  cfg: { enabled: boolean; role_arn?: string; region?: string; impersonate_sa?: string },
): Promise<{ config?: Record<string, string> }> {
  const c = await api.setCloudRemediation(id, cfg);
  revalidatePath("/settings");
  return { config: c.config };
}

// Set the tenant's LLM provider/model and (optionally) seal a new API key. An empty key keeps
// the existing one. The key is sealed server-side and never returned.
export async function setLLMConfig(
  provider: string,
  model: string,
  apiKey: string,
  baseURL?: string,
): Promise<{ provider: string; model: string; has_key: boolean; base_url?: string }> {
  const r = await api.setLLMConfig(provider, model, apiKey, baseURL);
  revalidatePath("/settings");
  return r;
}

// Set how much AI runs (deterministic-only / + engineer / + pentester) and the hard monthly ceiling.
// Passing the budget as undefined leaves an existing ceiling ALONE — changing the mode must never
// silently clear a budget the customer set.
export async function setAIMode(mode: string, monthlyBudgetUSD?: number) {
  const r = await api.setAIMode(mode, monthlyBudgetUSD);
  revalidatePath("/settings");
  return r;
}

// Set the repository PR-review-bot policy: enable inline review + a merge-gating check-run, and
// the severity floor that fails the check ("off" = comment-only). The live GitHub post stays
// gated on a connected GitHub App with the PR scope.
// Training consent — the customer end of the improvement loop. `by` names the human making
// the decision; the backend refuses a consent with no name, because an unattributed consent
// is not one anybody can stand behind later.
export async function setTrainingConsent(consented: boolean, by: string): Promise<void> {
  await api.setTrainingConsent(consented, by);
  revalidatePath("/settings");
}

export async function setPRBotPolicy(
  enabled: boolean,
  blockSeverity: string,
  installationId?: string,
): Promise<{ enabled: boolean; block_severity: string }> {
  const r = await api.setPRBotSettings(enabled, blockSeverity, installationId);
  revalidatePath("/settings");
  return { enabled: r.enabled, block_severity: r.block_severity };
}

// Practitioner layer — set who provides the human-in-the-loop (self_serve | msp | managed) and the
// named experts of record.
export async function setServiceModel(model: string): Promise<void> {
  await api.setServiceModel(model);
  revalidatePath("/settings");
}

export async function addPractitioner(body: {
  name: string;
  firm: string;
  credential: string;
  capacity: string;
  email: string;
}): Promise<void> {
  await api.addPractitioner(body);
  revalidatePath("/settings");
}

export async function deletePractitioner(id: string): Promise<void> {
  await api.deletePractitioner(id);
  revalidatePath("/settings");
}

// --- Trust Center ---------------------------------------------------------------------

// Save the buyer-facing share page's configuration. The server NORMALIZES what it is given —
// clamping a document that names open findings out of "public", dropping a wildcard
// auto-approve rule, bounding the grant window — and returns every correction it made. Those
// are passed straight back rather than swallowed: a config silently altered on save is one the
// owner believes says something it does not, and here that belief is about who can read their
// penetration-test report.
export async function setTrustCenter(cfg: TrustCenterConfig): Promise<{
  config: TrustCenterConfig;
  link: string;
  available: Record<string, boolean>;
  corrections: { field: string; reason: string }[];
}> {
  const r = await api.setTrustSettings(cfg);
  revalidatePath("/settings");
  return r;
}

// Rotate the share token: every outstanding link for THIS tenant stops working, and no other
// tenant's is touched.
export async function revokeTrustLink(): Promise<{ link: string; token_version: number }> {
  const r = await api.revokeTrustLink();
  revalidatePath("/settings");
  return r;
}

// Approve / deny / revoke one buyer's access request. On approve the response carries the access
// token ONCE — only its digest is stored — so the caller must show it immediately or it is gone.
export async function decideTrustRequest(
  id: string,
  decision: "approve" | "deny" | "revoke",
  by: string,
): Promise<{ access_token?: string; access_link?: string }> {
  const r = await api.decideTrustRequest(id, decision, by);
  revalidatePath("/settings");
  return { access_token: r.access_token, access_link: r.access_link };
}

// White-label branding for outward artifacts (VAPT report, public Trust Center). An empty name
// clears it — back to the product's own brand.
export async function setBranding(b: Branding): Promise<BrandingSettings> {
  const r = await api.setBranding(b);
  revalidatePath("/settings");
  return r;
}

// Push-to-Drata: configure the destination, and run the posture sync.
export async function setDrata(cfg: { api_key: string; workspace_id: number }) {
  const r = await api.setDrataSettings(cfg);
  revalidatePath("/settings");
  return r;
}
export async function syncDrata() {
  return api.syncDrata();
}

// Mint a workspace API key. Returns the key ONCE — the server stores only its digest — or the
// server's own refusal (a member, a bad scope, a lifetime past a year) as text rather than a throw,
// so the reason reaches the person instead of being swallowed by the action boundary.
export async function createAPIKey(k: { name: string; scopes: string[]; expires_in_days: number }):
  Promise<{ ok: true; token: string; prefix: string } | { ok: false; error: string }> {
  try {
    const r = await api.createAPIKey(k);
    revalidatePath("/settings");
    return { ok: true, token: r.token, prefix: r.key.prefix };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "could not create the key" };
  }
}

// Revoke a key. Recorded on the key rather than deleted, so what it did keeps its referent.
export async function revokeAPIKey(id: string): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.revokeAPIKey(id);
    revalidatePath("/settings");
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "could not revoke the key" };
  }
}

// Two-factor sign-in. Each returns the server's refusal as text (a wrong password, a stale code) so the
// reason reaches the person instead of being swallowed at the action boundary.
type Result<T> = ({ ok: true } & T) | { ok: false; error: string };
async function attempt<T>(fn: () => Promise<T>): Promise<Result<T>> {
  try {
    const r = await fn();
    revalidatePath("/settings");
    return { ok: true, ...r };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "that did not work" };
  }
}
export async function startTwoFactor(password: string) {
  return attempt(() => api.twoFactorSetup(password));
}
export async function confirmTwoFactor(code: string) {
  return attempt(() => api.twoFactorEnable(code));
}
export async function disableTwoFactor(b: { password: string; code?: string; recovery_code?: string }) {
  return attempt(() => api.twoFactorDisable(b));
}
export async function replaceRecoveryCodes(b: { password: string; code?: string; recovery_code?: string }) {
  return attempt(() => api.twoFactorRecoveryCodes(b));
}

// The workspace two-factor policy (owner). The server refuses switching it on until the owner has
// enrolled; that refusal is returned as text so the owner reads why.
export async function setRequireTwoFactor(require: boolean) {
  return attempt(() => api.setSecurityPolicy(require));
}

// Save or (with an empty issuer) remove the workspace's SSO provider. The server verifies the issuer
// against the provider's own metadata before saving; a refusal comes back as text.
export async function saveSSO(b: { issuer: string; client_id?: string; client_secret?: string; enforced?: boolean }) {
  return attempt(() => api.setSSO(b));
}
