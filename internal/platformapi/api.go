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
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/jobs"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Deps are the API's collaborators.
type Deps struct {
	Store      store.Store
	Connectors *connector.Registry
	Runner     *runner.Service
	Jobs       *jobs.Pool       // optional: runs rescans off the request path (nil → synchronous)
	Desk       Decider          // optional: the HITL desk (approvals decide)
	GRC        Posturer         // optional: the compliance system-of-record (posture)
	Vault      Sealer           // optional: seals OAuth tokens before persistence
	Recorder   *ledger.Recorder // optional: signs review request/resolve into the ledger
	Token      string           // static platform bearer token (required)
	PublicURL  string           // base URL for OAuth redirect_uri (e.g. https://app.example)
	// SlackSigningSecret verifies Slack interactive (approve/reject) callbacks. Empty
	// → the Slack endpoint returns 501.
	SlackSigningSecret string
	// WebhookSecret authenticates inbound provider webhooks (GitHub HMAC / GitLab token).
	// Empty → verification is skipped (a startup warning is logged; dev only).
	WebhookSecret string
	NewID         func() string
	// Prober drives live active-exploitation probes (the Phase-1 ActiveDriver). Nil →
	// active engagements fall back to the passive driver (no live exploitation). Set
	// only when the operator has enabled live active exploitation; per-engagement
	// explicit consent still gates every probe.
	Prober pentest.Prober
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
	mux.HandleFunc("POST /v1/webhooks/{kind}", d.auth(d.handleWebhook))
	mux.HandleFunc("GET /v1/findings", d.auth(d.handleFindings))
	mux.HandleFunc("GET /v1/findings/export", d.auth(d.handleFindingsExport))
	mux.HandleFunc("GET /v1/engagements", d.auth(d.handleEngagements))
	mux.HandleFunc("GET /v1/assets", d.auth(d.handleAssets))
	mux.HandleFunc("GET /v1/connections", d.auth(d.handleConnections))
	mux.HandleFunc("POST /v1/connections/{id}/quarantine", d.auth(d.handleQuarantineConnection)) // per-connection kill-switch (WRD-4)
	mux.HandleFunc("GET /v1/tenant", d.auth(d.handleGetTenant))                                  // the current tenant (org name/plan) for Settings
	mux.HandleFunc("POST /v1/killswitch", d.auth(d.handleKillSwitch))                            // global kill-switch: halt/resume all agent action
	mux.HandleFunc("GET /v1/ai-bom", d.auth(d.handleAIBOM))                                      // agent capability manifest (WRD-1): what the automation can touch
	mux.HandleFunc("GET /v1/trust-link", d.auth(d.handleTrustLink))                              // owner's shareable Trust Center token
	mux.HandleFunc("GET /v1/trust/{tenant}", d.handleTrust)                                      // PUBLIC, HMAC-token-gated; safe aggregates only
	mux.HandleFunc("GET /v1/assess", d.handlePublicAssess)                                       // PUBLIC PLG lead-magnet: read-only email-auth score for any domain
	mux.HandleFunc("POST /v1/lead", d.handleLead)                                                // PUBLIC: book-a-demo / talk-to-sales lead capture
	mux.HandleFunc("GET /v1/approvals", d.auth(d.handleApprovals))
	mux.HandleFunc("GET /v1/incidents", d.auth(d.handleIncidents))
	mux.HandleFunc("GET /v1/attack-paths", d.auth(d.handleAttackPaths))            // cross-surface correlation (unified cross-detection)
	mux.HandleFunc("GET /v1/issues", d.auth(d.handleIssues))                       // findings de-duplicated into unified issues (one issue, many signals)
	mux.HandleFunc("POST /v1/issues/ignore", d.auth(d.handleIgnoreIssue))          // suppress an issue (false-positive / accepted-risk)
	mux.HandleFunc("POST /v1/issues/unignore", d.auth(d.handleUnignoreIssue))      // restore a suppressed issue
	mux.HandleFunc("GET /v1/exclusions", d.auth(d.handleListExclusions))           // custom noise-filter rules (path/package/rule globs)
	mux.HandleFunc("POST /v1/exclusions", d.auth(d.handleAddExclusion))            // add an exclusion rule
	mux.HandleFunc("POST /v1/exclusions/delete", d.auth(d.handleDeleteExclusion))  // remove an exclusion rule
	mux.HandleFunc("POST /v1/runtime/events", d.auth(d.handleIngestRuntimeEvents)) // in-app firewall / RASP signal ingest (ADR-0007 Phase 0)
	mux.HandleFunc("GET /v1/runtime/events", d.auth(d.handleListRuntimeEvents))    // list runtime-protection events
	mux.HandleFunc("POST /v1/pentest", d.auth(d.handleCreatePentest))              // create + authorize a pentest engagement
	mux.HandleFunc("GET /v1/pentest", d.auth(d.handleListPentests))                // list engagements
	mux.HandleFunc("GET /v1/pentest/stats", d.auth(d.handlePentestStats))          // portfolio scorecard (verified_rate, SLA)
	mux.HandleFunc("GET /v1/pentest/{id}", d.auth(d.handleGetPentest))             // one engagement + findings
	mux.HandleFunc("POST /v1/pentest/{id}/run", d.auth(d.handleRunPentest))        // run/retest the engagement (passive, RoE-gated)
	mux.HandleFunc("GET /v1/pentest/{id}/report", d.auth(d.handlePentestReport))   // the engagement's VAPT report (md/json)
	mux.HandleFunc("GET /v1/events", d.auth(d.handleEvents))                       // SSE live state feed
	mux.HandleFunc("GET /v1/apps", d.auth(d.handleApps))
	mux.HandleFunc("POST /v1/rescan", d.auth(d.handleRescan))
	mux.HandleFunc("GET /v1/jobs", d.auth(d.handleJobs))
	mux.HandleFunc("GET /v1/jobs/{id}", d.auth(d.handleJob))
	mux.HandleFunc("POST /v1/approvals/{id}", d.auth(d.handleApprovalDecide))
	mux.HandleFunc("GET /v1/connect/{kind}", d.auth(d.handleConnectURL))
	mux.HandleFunc("GET /v1/connect/{kind}/callback", d.handleConnectCallback) // OAuth redirect; tenant in state
	mux.HandleFunc("GET /v1/posture/{framework}", d.auth(d.handlePosture))
	mux.HandleFunc("GET /v1/compliance/{framework}/report", d.auth(d.handleComplianceReport))
	mux.HandleFunc("GET /v1/questionnaire", d.auth(d.handleQuestionnaire))
	mux.HandleFunc("GET /v1/vapt/report", d.auth(d.handleVAPTReport))
	mux.HandleFunc("POST /v1/reviews", d.auth(d.handleCreateReview))
	mux.HandleFunc("GET /v1/reviews", d.auth(d.handleListReviews))
	mux.HandleFunc("POST /v1/reviews/{id}/resolve", d.auth(d.handleResolveReview))
	mux.HandleFunc("POST /v1/slack/interactive", d.handleSlackInteractive) // Slack-signed, not bearer-auth'd
	return mux
}

// auth resolves the request's tenant from either of two credentials and passes it to the
// handler: (1) the shared platform bearer token + an X-Tenant-ID header (operator / Slack /
// tests), or (2) a user session token, whose tenant comes from the session itself (the
// header cannot override it — no cross-tenant escalation).
func (d Deps) auth(h func(w http.ResponseWriter, r *http.Request, tenantID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Token != "" && r.Header.Get("Authorization") == "Bearer "+d.Token {
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
		if d.Token == "" || r.Header.Get("Authorization") != "Bearer "+d.Token {
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

	// authenticate the webhook before triggering ANY re-scan: a spoofed payload must not
	// be able to force scans. Verified against the shared secret when one is configured.
	if d.WebhookSecret != "" {
		if v, ok := conn.(connector.WebhookVerifier); ok {
			if err := v.VerifyWebhook(r.Header, body, d.WebhookSecret); err != nil {
				writeJSON(w, http.StatusUnauthorized, errBody("webhook verification failed"))
				return
			}
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
	respond(w, f, err)
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
	respond(w, t, err)
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
	writeJSON(w, http.StatusOK, t)
}

// handleAssets returns the tenant's monitored assets (what the agent continuously scans:
// repos, cloud accounts, domains, workspaces). Read-only; the console's "Monitored assets"
// view joins these against engagements for last-scanned time.
func (d Deps) handleAssets(w http.ResponseWriter, r *http.Request, tenantID string) {
	a, err := d.Store.ListAssets(r.Context(), tenantID)
	respond(w, a, err)
}

func (d Deps) handleApprovals(w http.ResponseWriter, r *http.Request, tenantID string) {
	a, err := d.Store.PendingApprovals(r.Context(), tenantID)
	respond(w, a, err)
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
		if err != nil {
			writeJSON(w, http.StatusBadGateway, errBody(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"assets_scanned": n})
		return
	}
	job, err := d.Jobs.Enqueue("rescan", tenantID, func(ctx context.Context) (any, error) {
		n, err := d.Runner.RescanTenant(ctx, tenantID)
		return map[string]any{"assets_scanned": n}, err
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
	writeJSON(w, http.StatusOK, v)
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
