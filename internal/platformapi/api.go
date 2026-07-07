// Package platformapi is the multi-tenant HTTP API for the autonomous security team
// platform (docs/autonomous-team.md §3.7). It wires the store + connectors + runner
// behind a small REST surface: receive provider webhooks (→ continuous re-scan), list
// a tenant's findings / engagements / connections, and read the HITL approval queue.
//
// Auth for the MVP is a static platform bearer token plus an X-Tenant-ID header that
// scopes every call; the store enforces isolation on that id. Real per-tenant OAuth
// sessions + the web dashboard come later — this is the API the front-end and Slack
// app consume.
package platformapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/coverage"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/email"
	"github.com/ClatTribe/tsengine/internal/jobs"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Deps are the API's collaborators.
type Deps struct {
	Store          store.Store
	Connectors     *connector.Registry
	Runner         *runner.Service
	Jobs           *jobs.Pool       // optional: runs rescans off the request path (nil → synchronous)
	Desk           Decider          // optional: the HITL desk (approvals decide)
	GRC            Posturer         // optional: the compliance system-of-record (posture)
	IncidentOpener IncidentOpener   // optional: opens incidents for event-driven ingest (identity/SaaS)
	Vault          Sealer           // optional: seals OAuth tokens before persistence
	Recorder       *ledger.Recorder // optional: signs review request/resolve into the ledger
	Token          string           // static platform bearer token (required)
	PublicURL      string           // base URL for OAuth redirect_uri (e.g. https://app.example)
	// AppURL is the browser-facing app base the OAuth callback lands the user back on after a
	// successful connect. When set, the callback 303-redirects to AppURL/assets?connected=<kind>
	// instead of writing a raw JSON blob into the browser (the post-connect "aha" moment). Empty
	// → JSON (back-compat for tests / non-browser callers).
	AppURL string
	// SlackSigningSecret verifies Slack interactive (approve/reject) callbacks. Empty
	// → the Slack endpoint returns 501.
	SlackSigningSecret string
	// WebhookSecret authenticates inbound provider webhooks (GitHub HMAC / GitLab token).
	// Empty → verification is skipped (a startup warning is logged; dev only).
	WebhookSecret string
	NewID         func() string
	// GitHubAPIBase overrides the GitHub REST base for the live SaaS-posture sync (default
	// https://api.github.com). Set only in tests (a fake API server).
	GitHubAPIBase string
	// Prober drives live active-exploitation probes (the Phase-1 ActiveDriver). Nil →
	// active engagements fall back to the passive driver (no live exploitation). Set
	// only when the operator has enabled live active exploitation; per-engagement
	// explicit consent still gates every probe.
	Prober pentest.Prober
	// Interactor observes out-of-band (OAST) callbacks so the deep (autonomous) driver can
	// prove blind classes (ADR-0008 D2). Nil → blind classes stay unproven leads (never a
	// false positive). Set when the operator wired a collaborator (TSENGINE_OAST_POLL_URL).
	Interactor pentest.Interactor
	// Browser renders DOM-XSS / client-side demonstrations in a headless browser (ADR-0008
	// D3). Nil → those classes stay unproven leads (the chromedp impl is sandbox-gated).
	Browser pentest.Prober
	// AgentLLM is the ModeDeep "D-agent" (ADR-0008): when set, the open-ended driver asks the model
	// to PROPOSE benign demonstration specs (validated deterministically downstream), instead of only
	// the heuristic generator. Wired from cloudengine.LLMFromEnv (cloud key OR a local Ollama). Nil →
	// the deterministic HeuristicSpecGen (today's behaviour). The model widens discovery only; the
	// deterministic predicate + the RoE Guard still gate every probe, so no LLM false positives.
	AgentLLM pentest.SpecLLM
	// LeadClient is the operator-global tool-calling client for the L2 Lead/translator (POST
	// /v1/l2/translate). Wired from l2.ClientFromEnv (Anthropic, OpenAI, or a local Ollama); a tenant's
	// own configured model takes precedence. Nil → the translator endpoint is gated (400).
	LeadClient l2.Client
	// CloudSnapshots persists a tenant's latest cloud inventory so the AI cloud engineer can run over
	// STORED cloud state (not only a freshly-posted inventory) — the prerequisite for the L2 generalist
	// delegating cloud-depth to cloudagent. Nil → no persistence (POST /v1/cloud/investigate still works
	// over the posted inventory; nothing is stored for later).
	CloudSnapshots cloudsnap.Store
	// Mailer sends transactional email (password-reset links, invites). Nil → a no-op (the
	// platform falls back to the in-UI temp-password flow and logs reset links for the operator).
	// Wired from email.FromEnv (SMTP_*); the SMTP provider is the credential-gated half.
	Mailer email.Mailer
	// WebDiscoverer runs the host-side XBOW discovery agent (internal/webagent) as the FIRST
	// stage of an ACTIVE/DEEP pentest run — so the engagement DISCOVERS new grounded vulns (not
	// only verifies existing scanner findings). Nil → defaultWebDiscoverer (webagent.Investigate).
	// The whole stage is gated on an available LLM + the ownership gate, so a run without a
	// configured model simply skips discovery and runs the verify drivers (honest, never a crash).
	// Injectable for tests (drive discovery deterministically without a live LLM loop).
	WebDiscoverer WebDiscoverer
	// Detector, when set, reconciles a pentest run's findings into incidents IMMEDIATELY (the
	// detect-&-respond "respond" half) — so a pentest that PROVES a high+/critical exploit opens
	// an incident right away instead of waiting for the next scheduled monitoring pass. The same
	// detector the runner uses; Reconcile dedups against open incidents, so bringing it forward is
	// safe. Nil → escalation happens on the next monitoring pass (today's behaviour).
	Detector *detect.Detector
}

// NewHandler returns the platform's HTTP handler.
func NewHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/tenants", d.platformAuth(d.handleCreateTenant)) // provisioning (no tenant header)
	// Real account auth: self-serve signup + email/password login (public), session-gated me/logout.
	mux.HandleFunc("POST /v1/auth/signup", d.handleSignup)
	mux.HandleFunc("POST /v1/auth/login", d.handleLogin)
	mux.HandleFunc("POST /v1/auth/logout", d.sessionAuth(d.handleLogout))
	mux.HandleFunc("GET /v1/auth/me", d.sessionAuth(d.handleMe))
	mux.HandleFunc("GET /v1/auth/team", d.sessionAuth(d.handleTeam))
	mux.HandleFunc("POST /v1/auth/invite", d.sessionAuth(d.handleInvite))
	mux.HandleFunc("POST /v1/auth/password", d.sessionAuth(d.handlePassword)) // change pw + clear MustChangePassword
	mux.HandleFunc("POST /v1/auth/forgot", d.handleForgotPassword)            // start reset (public; emails a one-time link, no enumeration)
	mux.HandleFunc("POST /v1/auth/reset", d.handleResetPassword)              // complete reset with the token
	mux.HandleFunc("POST /v1/webhooks/{kind}", d.auth(d.handleWebhook))
	mux.HandleFunc("GET /v1/findings", d.auth(d.handleFindings))
	mux.HandleFunc("GET /v1/findings/export", d.auth(d.handleFindingsExport))
	mux.HandleFunc("POST /v1/safechain/check", d.auth(d.handleSafeChain)) // install-time supply-chain gate (Safe Chain parity)
	mux.HandleFunc("GET /v1/engagements", d.auth(d.handleEngagements))
	mux.HandleFunc("GET /v1/assets", d.auth(d.handleAssets))
	mux.HandleFunc("POST /v1/assets", d.auth(d.handleCreateAsset))                                 // add a standalone scan target (web/api/domain/ip/image)
	mux.HandleFunc("POST /v1/assets/{id}/data-tier", d.auth(d.handleSetAssetDataTier))             // tier a repo by customer-data exposure
	mux.HandleFunc("POST /v1/assets/{id}/login-flow", d.auth(d.handleSetLoginFlow))                // configure authenticated web scanning (ADR 0010 Phase 3)
	mux.HandleFunc("POST /v1/assets/{id}/authz-test", d.auth(d.handleSetAuthzTest))                // configure BOLA/BFLA authz test (ADR 0010 Phase 1)
	mux.HandleFunc("POST /v1/assets/{id}/ownership/challenge", d.auth(d.handleOwnershipChallenge)) // issue DNS/file ownership token (p35 control)
	mux.HandleFunc("POST /v1/assets/{id}/ownership/verify", d.auth(d.handleOwnershipVerify))       // verify the token is published (grounded)
	mux.HandleFunc("GET /v1/connections", d.auth(d.handleConnections))
	mux.HandleFunc("DELETE /v1/connections/{id}", d.auth(d.handleDeleteConnection))                    // disconnect a connection (founder self-serve)
	mux.HandleFunc("POST /v1/connections/{id}/quarantine", d.auth(d.handleQuarantineConnection))       // per-connection kill-switch (WRD-4)
	mux.HandleFunc("POST /v1/connections/{id}/cloud-remediation", d.auth(d.handleSetCloudRemediation)) // per-tenant cloud write role (Bucket B)
	mux.HandleFunc("GET /v1/tenant", d.auth(d.handleGetTenant))                                        // the current tenant (org name/plan) for Settings
	mux.HandleFunc("GET /v1/settings/llm", d.auth(d.handleGetLLMSettings))                             // per-tenant LLM config (provider/model + has_key)
	mux.HandleFunc("PUT /v1/settings/llm", d.auth(d.handlePutLLMSettings))                             // set provider/model + seal the API key
	mux.HandleFunc("POST /v1/ci/pr-check", d.auth(d.handleCIPRCheck))                                  // CI entry point: PR changed-lines + findings → merge-gating attack-path check (wedge gap #3)
	mux.HandleFunc("GET /v1/settings/pr-bot", d.auth(d.handleGetPRBotSettings))                        // repository PR-review-bot policy (ADR 0010)
	mux.HandleFunc("PUT /v1/settings/pr-bot", d.auth(d.handlePutPRBotSettings))                        // set enable + merge-gating block severity
	mux.HandleFunc("GET /v1/settings/notifications", d.auth(d.handleGetNotifySettings))                // per-tenant Slack incident webhook (has_slack_webhook)
	mux.HandleFunc("PUT /v1/settings/notifications", d.auth(d.handlePutNotifySettings))                // set + seal the tenant's Slack incident webhook (Bucket B)
	mux.HandleFunc("GET /v1/settings/jira", d.auth(d.handleGetJiraSettings))                           // per-tenant Jira ticketing destination (base/email/project + has_token)
	mux.HandleFunc("PUT /v1/settings/jira", d.auth(d.handlePutJiraSettings))                           // set + seal the tenant's Jira API token (Bucket B)
	mux.HandleFunc("GET /v1/settings/escalation", d.auth(d.handleGetEscalationSettings))               // per-tenant incident escalation matrix (MDR/SOC)
	mux.HandleFunc("PUT /v1/settings/escalation", d.auth(d.handlePutEscalationSettings))               // set the escalation tiers (severity → channels)
	mux.HandleFunc("GET /v1/settings/sla", d.auth(d.handleGetSLASettings))                             // per-tenant remediation SLA policy (ack/resolve targets)
	mux.HandleFunc("PUT /v1/settings/sla", d.auth(d.handlePutSLASettings))                             // set the per-severity SLA targets
	mux.HandleFunc("GET /v1/settings/compliance-scope", d.auth(d.handleGetComplianceScope))            // target frameworks + applicability profile (scope before analysis)
	mux.HandleFunc("PUT /v1/settings/compliance-scope", d.auth(d.handlePutComplianceScope))            // set target frameworks + profile
	mux.HandleFunc("GET /v1/compliance/readiness", d.auth(d.handleComplianceReadiness))                // connect-this-first checklist for the target frameworks
	mux.HandleFunc("GET /v1/compliance/by-asset", d.auth(d.handleComplianceByAsset))                   // per-asset compliance signal ("is this asset compliant?") — grounded, never false-compliant
	mux.HandleFunc("GET /v1/compliance/oscal", d.auth(d.handleComplianceOSCAL))                        // control coverage as a NIST OSCAL component-definition (GRC-tool-ingestible)
	mux.HandleFunc("GET /v1/security/by-asset", d.auth(d.handleSecurityByAsset))                       // per-asset security posture ("is this asset secure?") — FP-aware, never a false "all clear"
	mux.HandleFunc("GET /v1/custom-frameworks", d.auth(d.handleListCustomFrameworks))                  // bring-your-own-framework: list
	mux.HandleFunc("POST /v1/custom-frameworks", d.auth(d.handleAddCustomFramework))                   // define a custom framework (controls map to findings/CWEs/built-in controls)
	mux.HandleFunc("DELETE /v1/custom-frameworks/{id}", d.auth(d.handleDeleteCustomFramework))         // remove a custom framework
	mux.HandleFunc("GET /v1/custom-frameworks/{id}/posture", d.auth(d.handleCustomFrameworkPosture))   // derived posture + coverage from live findings
	mux.HandleFunc("GET /v1/maintenance-windows", d.auth(d.handleListMaintenanceWindows))              // planned change-freeze windows (suppress alerting)
	mux.HandleFunc("POST /v1/maintenance-windows", d.auth(d.handleAddMaintenanceWindow))               // schedule a window
	mux.HandleFunc("DELETE /v1/maintenance-windows/{id}", d.auth(d.handleDeleteMaintenanceWindow))     // cancel a window
	mux.HandleFunc("GET /v1/contacts", d.auth(d.handleListContacts))                                   // on-call escalation roster (names + numbers)
	mux.HandleFunc("POST /v1/contacts", d.auth(d.handleAddContact))                                    // add a contact
	mux.HandleFunc("DELETE /v1/contacts/{id}", d.auth(d.handleDeleteContact))                          // remove a contact
	mux.HandleFunc("POST /v1/killswitch", d.auth(d.handleKillSwitch))                                  // global kill-switch: halt/resume all agent action
	mux.HandleFunc("GET /v1/ai-bom", d.auth(d.handleAIBOM))                                            // agent capability manifest (WRD-1): what the automation can touch
	mux.HandleFunc("GET /v1/trust-link", d.auth(d.handleTrustLink))                                    // owner's shareable Trust Center token
	mux.HandleFunc("GET /v1/trust/{tenant}", d.handleTrust)                                            // PUBLIC, HMAC-token-gated; safe aggregates only
	mux.HandleFunc("GET /v1/assess", d.handlePublicAssess)                                             // PUBLIC PLG lead-magnet: read-only email-auth score for any domain
	mux.HandleFunc("POST /v1/lead", d.handleLead)                                                      // PUBLIC: book-a-demo / talk-to-sales lead capture
	mux.HandleFunc("GET /v1/assess/badge", d.handleAssessBadge)                                        // PUBLIC: embeddable SVG grade badge (viral loop)
	mux.HandleFunc("GET /v1/approvals", d.auth(d.handleApprovals))
	mux.HandleFunc("GET /v1/actions", d.auth(d.handleActions))   // all remediations + fix-verification status
	mux.HandleFunc("GET /v1/coverage", d.auth(d.handleCoverage)) // per-asset "what was actually tested"
	mux.HandleFunc("GET /v1/incidents", d.auth(d.handleIncidents))
	mux.HandleFunc("POST /v1/incidents/{id}/ack", d.auth(d.handleAckIncident))              // human takes ownership → stops timed auto-escalation
	mux.HandleFunc("GET /v1/risks", d.auth(d.handleListRisks))                              // risk register (vCISO artifact) + board summary
	mux.HandleFunc("POST /v1/risks", d.auth(d.handleCreateRisk))                            // add a manual risk
	mux.HandleFunc("POST /v1/risks/seed", d.auth(d.handleSeedRisks))                        // propose candidates from findings (grounded)
	mux.HandleFunc("POST /v1/risks/{id}/decision", d.auth(d.handleDecideRisk))              // HITL: named human accepts/treats → signed ledger
	mux.HandleFunc("GET /v1/audits", d.auth(d.handleListAudits))                            // audit engagements + per-engagement attestation summary
	mux.HandleFunc("POST /v1/audits", d.auth(d.handleCreateAudit))                          // open an engagement (seeds controls from posture)
	mux.HandleFunc("POST /v1/audits/{id}/attest", d.auth(d.handleAttestControl))            // HITL: external auditor's per-control verdict → signed ledger
	mux.HandleFunc("POST /v1/audits/{id}/issue", d.auth(d.handleIssueAudit))                // mark issued (named auditor + all controls attested)
	mux.HandleFunc("GET /v1/program", d.auth(d.handleListProgram))                          // security-program policy register + board summary
	mux.HandleFunc("POST /v1/program/seed", d.auth(d.handleSeedProgram))                    // seed the standard policy set (drafts)
	mux.HandleFunc("POST /v1/program/{id}/publish", d.auth(d.handlePublishPolicy))          // HITL: named owner publishes → signed ledger
	mux.HandleFunc("POST /v1/program/{id}/ack", d.auth(d.handleAckPolicy))                  // a named member acknowledges a published policy
	mux.HandleFunc("GET /v1/practitioners", d.auth(d.handleGetPractitioners))               // service model + practitioners of record (who provides HITL)
	mux.HandleFunc("POST /v1/practitioners", d.auth(d.handleAddPractitioner))               // add a named practitioner (capacity: internal|msp|managed)
	mux.HandleFunc("DELETE /v1/practitioners/{id}", d.auth(d.handleDeletePractitioner))     // remove a practitioner
	mux.HandleFunc("PUT /v1/settings/service-model", d.auth(d.handleSetServiceModel))       // set who provides the HITL (self_serve|msp|managed)
	mux.HandleFunc("GET /v1/practitioner/queue", d.platformAuth(d.handlePractitionerQueue)) // cross-tenant practitioner desk (platform-token gated)
	// Operator (cross-tenant practitioner) auth + console — a SEPARATE namespace from tenant auth.
	mux.HandleFunc("POST /v1/operator", d.platformAuth(d.handleCreateOperator))                                                // provision an operator account (deployment-operator gated)
	mux.HandleFunc("POST /v1/operator/login", d.handleOperatorLogin)                                                           // operator email+password login
	mux.HandleFunc("POST /v1/operator/logout", d.operatorAuth(d.handleOperatorLogout))                                         // end the operator session
	mux.HandleFunc("GET /v1/operator/me", d.operatorAuth(d.handleOperatorMe))                                                  // the current operator
	mux.HandleFunc("GET /v1/operator/queue", d.operatorAuth(d.handleOperatorQueue))                                            // the operator's own cross-tenant work queue
	mux.HandleFunc("POST /v1/operator/tenants/{tenant}/risks/{id}/decision", d.operatorAuth(d.handleOperatorDecideRisk))       // act-on-behalf: decide a risk for an assigned client
	mux.HandleFunc("POST /v1/operator/tenants/{tenant}/policies/{id}/publish", d.operatorAuth(d.handleOperatorPublishPolicy))  // act-on-behalf: publish a policy for an assigned client
	mux.HandleFunc("POST /v1/operator/tenants/{tenant}/pentests/{id}/signoff", d.operatorAuth(d.handleOperatorSignoffPentest)) // act-on-behalf: sign off a pentest report for an assigned client
	mux.HandleFunc("POST /v1/operator/tenants/{tenant}/audits/{id}/attest", d.operatorAuth(d.handleOperatorAttestControl))     // act-on-behalf: attest a control for an assigned client
	mux.HandleFunc("GET /v1/soc-metrics", d.auth(d.handleSOCMetrics))                                                          // SOC-performance scorecard (SLA compliance %, MTTA/MTTR, aging)
	mux.HandleFunc("GET /v1/attack-paths", d.auth(d.handleAttackPaths))                                                        // cross-surface correlation (unified cross-detection)
	mux.HandleFunc("GET /v1/issues", d.auth(d.handleIssues))                                                                   // findings de-duplicated into unified issues (one issue, many signals)
	mux.HandleFunc("GET /v1/triage-funnel", d.auth(d.handleTriageFunnel))                                                      // auto-triage funnel: % of raw findings the engine handled automatically
	mux.HandleFunc("POST /v1/issues/ignore", d.auth(d.handleIgnoreIssue))                                                      // suppress an issue (false-positive / accepted-risk)
	mux.HandleFunc("POST /v1/issues/unignore", d.auth(d.handleUnignoreIssue))                                                  // restore a suppressed issue
	mux.HandleFunc("GET /v1/exclusions", d.auth(d.handleListExclusions))                                                       // custom noise-filter rules (path/package/rule globs)
	mux.HandleFunc("POST /v1/exclusions", d.auth(d.handleAddExclusion))                                                        // add an exclusion rule
	mux.HandleFunc("POST /v1/exclusions/delete", d.auth(d.handleDeleteExclusion))                                              // remove an exclusion rule
	mux.HandleFunc("POST /v1/runtime/events", d.auth(d.handleIngestRuntimeEvents))                                             // in-app firewall / RASP signal ingest (ADR-0007 Phase 0)
	mux.HandleFunc("POST /v1/identity/events", d.auth(d.handleIngestIdentityEvents))                                           // real-time identity-threat (ITDR) ingest (ADR 0010 Phase 5)
	mux.HandleFunc("POST /v1/cloud/events", d.auth(d.handleIngestCloudEvents))                                                 // cloud control-plane CDR ingest (CloudTrail/GCP/Azure → live-action detection)
	mux.HandleFunc("POST /v1/registry/reconcile", d.auth(d.handleRegistryReconcile))                                           // container scan-on-push decision (ADR 0010 Phase 4)
	mux.HandleFunc("POST /v1/import/postman", d.auth(d.handlePostmanImport))                                                   // api: Postman collection → endpoint inventory
	mux.HandleFunc("POST /v1/osint/ingest", d.auth(d.handleIngestOSINT))                                                       // OSINT external-exposure snapshot → findings (ADR 0011)
	mux.HandleFunc("POST /v1/osint/scan", d.auth(d.handleOSINTScan))                                                           // LIVE keyless OSINT (crt.sh CT) over the tenant's domains
	mux.HandleFunc("POST /v1/cloud/inventory", d.auth(d.handleIngestAWSInventory))                                             // live collector: posted raw AWS state → attack-path Inventory → stored (wedge gap #1)
	mux.HandleFunc("POST /v1/cloud/investigate", d.auth(d.handleCloudInvestigate))                                             // AI Cloud Engineer (cloudagent) over a posted inventory (LLM-gated)
	mux.HandleFunc("GET /v1/cloud/investigate", d.auth(d.handleCloudInvestigationView))                                        // stored cloud-agent attack paths
	mux.HandleFunc("POST /v1/l2/translate", d.auth(d.handleL2Translate))                                                       // L2 Lead → developer/founder-facing consultant deliverable (LLM-gated)
	mux.HandleFunc("POST /v1/findings/{id}/autofix", d.auth(d.handleAutofix))                                                  // AI autofix — LLM-generated code patch for a finding (LLM-gated)
	mux.HandleFunc("POST /v1/issues/investigate", d.auth(d.handleIssueInvestigate))                                            // AI per-issue investigation (key in body — keys contain '/') — chain + blast radius (always) + root-cause/fix narrative (LLM-gated)
	mux.HandleFunc("GET /v1/ai-analyses", d.auth(d.handleListAIAnalyses))                                                      // persisted AI Security Engineer analyses (Triage/Investigate) — a run survives navigation; ?kind= filter
	mux.HandleFunc("POST /v1/apiauthz/discover", d.auth(d.handleAuthzDiscover))                                                // API BOLA/BFLA discovery — LLM proposes candidate authz tests (LLM-gated)
	mux.HandleFunc("POST /v1/tls/scan", d.auth(d.handleTLSScan))                                                               // TLS/SSL posture — host-side handshake assessment (no sandbox, SSRF-screened)
	mux.HandleFunc("GET /v1/osint", d.auth(d.handleOSINTView))                                                                 // OSINT "External exposure" view + summary
	mux.HandleFunc("POST /v1/saas/{provider}/snapshot", d.auth(d.handleIngestSaaSSnapshot))                                    // SaaS posture (SSPM) snapshot → findings
	mux.HandleFunc("POST /v1/saas/github_org/sync", d.auth(d.handleSyncSaaSGitHub))                                            // LIVE GitHub-org SSPM via the onboarded token (Bucket A)
	mux.HandleFunc("POST /v1/cloud/drift", d.auth(d.handleCloudDrift))                                                         // continuous config-snapshot drift: prev+cur inventory → change-control findings
	mux.HandleFunc("POST /v1/cloud/search", d.auth(d.handleCloudSearch))                                                       // "search your cloud like a database" — query the inventory + relationships
	mux.HandleFunc("POST /v1/tprm/ingest", d.auth(d.handleTPRMIngest))                                                         // third-party / vendor risk (TPRM) inventory → findings
	mux.HandleFunc("POST /v1/devices/ingest", d.auth(d.handleDevicePostureIngest))                                             // endpoint/device posture (MDM-lite) inventory → findings
	mux.HandleFunc("GET /v1/posture/sources", d.auth(d.handlePostureView))                                                     // unified vendor/device/cloud-drift posture-source view
	mux.HandleFunc("GET /v1/runtime/events", d.auth(d.handleListRuntimeEvents))                                                // list runtime-protection events
	mux.HandleFunc("POST /v1/pentest", d.auth(d.handleCreatePentest))                                                          // create + authorize a pentest engagement
	mux.HandleFunc("POST /v1/assets/{id}/pentest", d.auth(d.handleCreatePentestFromAsset))                                     // create a pentest pre-scoped to an asset ("pentest this asset")
	mux.HandleFunc("GET /v1/pentest", d.auth(d.handleListPentests))                                                            // list engagements
	mux.HandleFunc("GET /v1/pentest/stats", d.auth(d.handlePentestStats))                                                      // portfolio scorecard (verified_rate, SLA)
	mux.HandleFunc("GET /v1/pentest/{id}", d.auth(d.handleGetPentest))                                                         // one engagement + findings
	mux.HandleFunc("GET /v1/pentest/{id}/readiness", d.auth(d.handlePentestReadiness))                                         // pre-flight: per-target ownership + consent + LLM-key status
	mux.HandleFunc("GET /v1/pentest/{id}/progress", d.auth(d.handlePentestProgress))                                           // live run progress (requests sent / findings so far) for the watch-it-work view
	mux.HandleFunc("POST /v1/pentest/{id}/run", d.auth(d.handleRunPentest))                                                    // run/retest the engagement (passive, RoE-gated)
	mux.HandleFunc("GET /v1/pentest/{id}/report", d.auth(d.handlePentestReport))                                               // the engagement's VAPT report (md/json)
	mux.HandleFunc("POST /v1/pentest/{id}/signoff", d.auth(d.handleSignoffPentest))                                            // HITL: named human signs the report → signed ledger
	mux.HandleFunc("POST /v1/pentest/{id}/schedule", d.auth(d.handleSetPentestSchedule))                                       // set a recurring re-test cadence (safe passive re-verify)
	mux.HandleFunc("GET /v1/events", d.auth(d.handleEvents))                                                                   // SSE live state feed
	mux.HandleFunc("GET /v1/apps", d.auth(d.handleApps))
	mux.HandleFunc("GET /v1/saas-apps", d.auth(d.handleSaaSApps))            // SaaS-app discovery view (inventory + portfolio summary)
	mux.HandleFunc("GET /v1/identities", d.auth(d.handleNonHumanIdentities)) // non-human / AI-agent identity posture (ACSP agentic lens)
	mux.HandleFunc("POST /v1/rescan", d.auth(d.handleRescan))
	mux.HandleFunc("GET /v1/jobs", d.auth(d.handleJobs))
	mux.HandleFunc("GET /v1/jobs/{id}", d.auth(d.handleJob))
	mux.HandleFunc("POST /v1/approvals/{id}", d.auth(d.handleApprovalDecide))
	mux.HandleFunc("GET /v1/connect/{kind}", d.auth(d.handleConnectURL))
	mux.HandleFunc("GET /v1/connect/{kind}/callback", d.handleConnectCallback) // OAuth redirect; SIGNED tenant in state (oauthstate.go)
	mux.HandleFunc("GET /v1/posture", d.auth(d.handlePostureSummary))          // all-framework posture summary in one call (dashboard/compliance/reports)
	mux.HandleFunc("GET /v1/posture/{framework}", d.auth(d.handlePosture))
	mux.HandleFunc("GET /v1/compliance/{framework}/report", d.auth(d.handleComplianceReport))
	mux.HandleFunc("GET /v1/compliance/{framework}/fixes", d.auth(d.handleComplianceFixes))              // compliance→remediation bridge: which gaps are fixable now (findings + queued actions)
	mux.HandleFunc("POST /v1/compliance/{framework}/remediation", d.auth(d.handleComplianceRemediation)) // vCISO "how do I close this gap?" — LLM remediation guidance (gated)
	mux.HandleFunc("POST /v1/compliance/{framework}/advisor", d.auth(d.handleComplianceAdvisor))         // vCISO advisor — prioritized audit-readiness roadmap over coverage+gaps+readiness (gated)
	mux.HandleFunc("GET /v1/questionnaire", d.auth(d.handleQuestionnaire))
	mux.HandleFunc("GET /v1/vapt/report", d.auth(d.handleVAPTReport))
	mux.HandleFunc("POST /v1/reviews", d.auth(d.handleCreateReview))
	mux.HandleFunc("GET /v1/reviews", d.auth(d.handleListReviews))
	mux.HandleFunc("POST /v1/reviews/{id}/resolve", d.auth(d.handleResolveReview))
	mux.HandleFunc("POST /v1/slack/interactive", d.handleSlackInteractive) // Slack-signed, not bearer-auth'd
	return mux
}

// bearerOK reports whether the request carries the configured platform bearer token, compared in
// CONSTANT TIME (so a remote timing side-channel can't recover the token byte-by-byte). An empty
// configured token never matches — a misconfigured deployment can't be bypassed with an empty header.
func (d Deps) bearerOK(r *http.Request) bool {
	if d.Token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+d.Token)) == 1
}

// auth resolves the request's tenant from either of two credentials and passes it to the
// handler: (1) the shared platform bearer token + an X-Tenant-ID header (operator / Slack /
// tests), or (2) a user session token, whose tenant comes from the session itself (the
// header cannot override it — no cross-tenant escalation).
func (d Deps) auth(h func(w http.ResponseWriter, r *http.Request, tenantID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.bearerOK(r) {
			tenantID := r.Header.Get("X-Tenant-ID")
			if tenantID == "" {
				writeJSON(w, http.StatusBadRequest, errBody("missing X-Tenant-ID"))
				return
			}
			h(w, r, tenantID)
			return
		}
		if s, ok := d.resolveSession(r); ok {
			// A member provisioned with a temporary password must set their own before the
			// app unlocks (the owner who issued the temp password knows it). The auth-
			// management endpoints (me/logout/password) use sessionAuth, not this gate, so
			// the user can still see who they are and rotate the password.
			if u, err := d.Store.GetUser(r.Context(), s.UserID); err == nil && u.MustChangePassword {
				writeJSON(w, http.StatusForbidden, errCode("set a new password to continue", "password_change_required"))
				return
			}
			h(w, r, s.TenantID)
			return
		}
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
	}
}

// platformAuth enforces only the platform bearer token (no tenant scope) — for
// provisioning endpoints that create/operate across tenants.
func (d Deps) platformAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.bearerOK(r) {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		h(w, r)
	}
}

// handleCreateTenant provisions a new tenant (the start of onboarding). Returns the
// tenant with its generated id, which the caller then uses as X-Tenant-ID.
func (d Deps) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Plan string `json:"plan,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || body.Name == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a tenant needs a name"))
		return
	}
	t := platform.Tenant{ID: d.newID("ten"), Name: body.Name, Plan: body.Plan}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

// handleWebhook turns a provider event into triggers and re-scans the matching assets.
func (d Deps) handleWebhook(w http.ResponseWriter, r *http.Request, tenantID string) {
	kind := r.PathValue("kind")
	conn, err := d.Connectors.Get(kind)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))

	// authenticate the webhook before triggering ANY re-scan: a spoofed payload must not be able to
	// force scans. If the connector CAN verify its provider signature (GitHub/GitLab HMAC), that check
	// is MANDATORY — fail closed when the operator hasn't configured the secret, rather than silently
	// accepting an unverified provider payload (the fail-open gap). Connectors with no signature scheme
	// fall through to the route's bearer auth (d.auth).
	if v, ok := conn.(connector.WebhookVerifier); ok {
		if d.WebhookSecret == "" {
			writeJSON(w, http.StatusServiceUnavailable, errBody("webhook verification unavailable: set TSENGINE_WEBHOOK_SECRET"))
			return
		}
		if err := v.VerifyWebhook(r.Header, body, d.WebhookSecret); err != nil {
			writeJSON(w, http.StatusUnauthorized, errBody("webhook verification failed"))
			return
		}
	}

	// find the tenant's active connection of this kind to attribute the event
	conns, _ := d.Store.ListConnections(r.Context(), tenantID)
	var matched bool
	var engagements int
	for _, c := range conns {
		if c.Kind != kind {
			continue
		}
		matched = true
		trigs, werr := conn.Watch(r.Context(), c, body)
		if werr != nil {
			writeJSON(w, http.StatusBadRequest, errBody(werr.Error()))
			return
		}
		for _, t := range trigs {
			if _, rerr := d.Runner.OnTrigger(r.Context(), t); rerr == nil {
				engagements++
			}
		}
	}
	if !matched {
		writeJSON(w, http.StatusNotFound, errBody("no "+kind+" connection for tenant"))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"engagements_started": engagements})
}

func (d Deps) handleFindings(w http.ResponseWriter, r *http.Request, tenantID string) {
	f, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{
		Severity: severityParam(r), Status: r.URL.Query().Get("status"),
	})
	if err != nil {
		respond(w, nil, err)
		return
	}
	// Annotate each finding with its blast radius (impact) so the report surface can show "reaches a crown
	// jewel" — the same signal incidents carry (#563). The FP-control (verification/confidence) is already on
	// the finding.
	respond(w, d.annotateFindingsImpact(r.Context(), tenantID, f), nil)
}

func (d Deps) handleEngagements(w http.ResponseWriter, r *http.Request, tenantID string) {
	e, err := d.Store.ListEngagements(r.Context(), tenantID)
	respond(w, e, err)
}

func (d Deps) handleConnections(w http.ResponseWriter, r *http.Request, tenantID string) {
	c, err := d.Store.ListConnections(r.Context(), tenantID)
	respond(w, redactConnections(c), err)
}

// handleGetTenant returns the caller's own tenant (org name, plan, created) for the
// Settings screen. Tenant-scoped: a tenant can only read itself.
func (d Deps) handleGetTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	respond(w, t.Redacted(), nil) // never leak the sealed LLM key ref
}

// handleKillSwitch engages/disengages the tenant's global kill-switch (agentic-SMB spec
// OM-3 / TS-5). While engaged the platform takes NO autonomous agent action for the tenant
// — no new scans, no remediation writes (the hitl desk + runner fail closed). The toggle
// is signed into the ledger as a governance action. Returns the updated tenant.
func (d Deps) handleKillSwitch(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Halted bool `json:"halted"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	t.AgentsHalted = body.Halted
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		state := "resumed"
		if body.Halted {
			state = "halted"
		}
		d.Recorder.Record("kill-switch toggled", "kill_switch",
			map[string]any{"tenant_id": tenantID, "halted": body.Halted}, "agent automation "+state)
	}
	writeJSON(w, http.StatusOK, t.Redacted())
}

// handleAssets returns the tenant's monitored assets (what the agent continuously scans:
// repos, cloud accounts, domains, workspaces). Read-only; the console's "Monitored assets"
// view joins these against engagements for last-scanned time.
func (d Deps) handleAssets(w http.ResponseWriter, r *http.Request, tenantID string) {
	a, err := d.Store.ListAssets(r.Context(), tenantID)
	if err != nil {
		respond(w, a, err)
		return
	}
	views := make([]assetView, len(a))
	for i := range a {
		views[i] = viewAsset(a[i]) // surface data_tier + label without the UX parsing Meta
	}
	respond(w, views, nil)
}

func (d Deps) handleApprovals(w http.ResponseWriter, r *http.Request, tenantID string) {
	a, err := d.Store.PendingApprovals(r.Context(), tenantID)
	respond(w, a, err)
}

// actionsView wraps the action list with a fix-verification roll-up — the KF#4 answer surfaced as a
// single number ("we don't just fix, we confirm the fix worked"). Grounded: rates are computed only
// over APPLIED actions that carry finding keys (the verifiable set), never inflated by un-verifiable ones.
type actionsView struct {
	Actions      []platform.Action `json:"actions"`
	Applied      int               `json:"applied"`       // applied actions that are verifiable (carry finding keys)
	Verified     int               `json:"verified"`      // re-tested at least once
	ConfirmedFix int               `json:"confirmed_fix"` // re-test proved the fix closed the finding(s)
	StillPresent int               `json:"still_present"` // re-test showed the fix did NOT close it (reopen)
}

// handleActions returns ALL the tenant's remediation actions with their fix-verification state —
// the durable answer to "did the fix actually work?" (KF#4: most teams never retest a fix).
func (d Deps) handleActions(w http.ResponseWriter, r *http.Request, tenantID string) {
	acts, err := d.Store.ListActions(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	v := actionsView{Actions: acts}
	for _, a := range acts {
		if a.Status != platform.ActApplied || len(a.FindingKeys) == 0 {
			continue
		}
		v.Applied++
		if a.Verification == nil {
			continue
		}
		v.Verified++
		switch a.Verification.Status {
		case "fixed":
			v.ConfirmedFix++
		case "still_present":
			v.StillPresent++
		}
	}
	respond(w, v, nil)
}

// handleCoverage returns the per-asset "what was actually tested" view — the declared tools each scan
// runs, when each asset was last scanned, and which tools surfaced findings (the report's "52% lack
// visibility into what was tested"). Grounded: never-scanned assets read scanned:false, never "covered".
func (d Deps) handleCoverage(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	engs, err := d.Store.ListEngagements(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	respond(w, coverage.Compute(assets, findings, engs), nil)
}

// handleApps returns the tenant's third-party OAuth app inventory (the SaaS/app
// inventory for compliance — all apps with access, not just the risky ones).
func (d Deps) handleApps(w http.ResponseWriter, r *http.Request, tenantID string) {
	apps, err := d.Store.ListThirdPartyApps(r.Context(), tenantID)
	respond(w, apps, err)
}

// handleRescan triggers a re-scan of all the tenant's assets (the API behind the
// dashboard's "Scan now"). With a job pool configured it enqueues the scan and returns
// 202 + a job id to poll (scans can be long — they must not block the request); without
// one it runs synchronously and returns the asset count (back-compat, used by tests).
func (d Deps) handleRescan(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.Runner == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("scanning not configured"))
		return
	}
	if d.Jobs == nil {
		n, err := d.Runner.RescanTenant(r.Context(), tenantID)
		// Partial success is success: RescanTenant continues past a per-asset error (e.g. one stale/401
		// connection) and returns how many it DID scan + the first error. A founder's "Scan now" must not
		// report a total failure because one degraded connection errored — only fail if nothing scanned.
		if err != nil && n == 0 {
			writeJSON(w, http.StatusBadGateway, errBody(err.Error()))
			return
		}
		res := map[string]any{"assets_scanned": n}
		if err != nil {
			res["warning"] = err.Error()
		}
		writeJSON(w, http.StatusOK, res)
		return
	}
	job, err := d.Jobs.Enqueue("rescan", tenantID, func(ctx context.Context) (any, error) {
		n, scanErr := d.Runner.RescanTenant(ctx, tenantID)
		res := map[string]any{"assets_scanned": n}
		if scanErr != nil {
			res["warning"] = scanErr.Error()
		}
		// Only a total failure (nothing scanned) fails the job; a partial pass succeeds with a warning,
		// so one stale connection never makes the whole "Scan now" read as failed.
		if scanErr != nil && n == 0 {
			return res, scanErr
		}
		return res, nil
	})
	if errors.Is(err, jobs.ErrBusy) {
		writeJSON(w, http.StatusTooManyRequests, errBody(err.Error()))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// handleJob returns a single job's status — tenant-scoped (a tenant can only read its own).
func (d Deps) handleJob(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.Jobs == nil {
		writeJSON(w, http.StatusNotFound, errBody("no job runner"))
		return
	}
	job, ok := d.Jobs.Get(r.PathValue("id"))
	if !ok || job.TenantID != tenantID {
		writeJSON(w, http.StatusNotFound, errBody("job not found"))
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// handleJobs lists the tenant's recent jobs (newest first).
func (d Deps) handleJobs(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.Jobs == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, d.Jobs.List(tenantID))
}

// handleIncidents returns the tenant's OPEN incidents (the continuous-monitoring view:
// what's newly broken since a prior pass). ?status=all returns resolved ones too.
func (d Deps) handleIncidents(w http.ResponseWriter, r *http.Request, tenantID string) {
	all, err := d.Store.ListIncidents(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	d.annotateSLA(r.Context(), tenantID, all)         // transient sla_breach per incident (read-time)
	d.annotateBlastRadius(r.Context(), tenantID, all) // transient blast_radius per incident (read-time impact)
	if r.URL.Query().Get("status") == "all" {
		respond(w, all, nil)
		return
	}
	open := make([]platform.Incident, 0, len(all))
	for _, i := range all {
		if i.Status == platform.IncidentOpen {
			open = append(open, i)
		}
	}
	respond(w, open, nil)
}

// --- helpers ---

func respond(w http.ResponseWriter, v any, err error) {
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, emptyIfNilSlice(v))
}

// emptyIfNilSlice replaces a nil slice with a non-nil empty one so it serializes as [] not null.
// A JSON null crashes a frontend that does .map/.filter on the response (the Go nil-slice →
// JSON-null footgun); every list endpoint must return [] when empty, like the rest already do.
func emptyIfNilSlice(v any) any {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice && rv.IsNil() {
		return reflect.MakeSlice(rv.Type(), 0, 0).Interface()
	}
	return v
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

// errCode is errBody plus a machine-readable code the frontend can branch on (e.g.
// "password_change_required" → route to the set-password screen).
func errCode(msg, code string) map[string]string {
	return map[string]string{"error": msg, "code": code}
}

func severityParam(r *http.Request) types.Severity {
	return types.Severity(r.URL.Query().Get("severity"))
}

// redactConnections strips the SecretRef before a connection ever leaves the API —
// the OAuth token reference must never reach a client.
func redactConnections(cs []platform.Connection) []platform.Connection {
	out := make([]platform.Connection, len(cs))
	for i, c := range cs {
		c.SecretRef = ""
		out[i] = c
	}
	return out
}
