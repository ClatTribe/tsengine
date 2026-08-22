package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Decider is the HITL desk surface the API needs (satisfied by *hitl.Desk).
type Decider interface {
	Decide(ctx context.Context, tenantID, actionID string, v hitl.Verdict) (platform.Action, error)
}

// Submitter queues a proposed remediation Action at the HITL desk — tier-gated, so nothing risky
// auto-applies. Satisfied by *hitl.Desk. Separate from Decider (a new method on that interface would
// break its test fakes); optional on Deps.
type Submitter interface {
	Submit(ctx context.Context, a platform.Action) (platform.Action, error)
}

// Posturer is the GRC surface the API needs (satisfied by *grc.GRC): the raw control
// state plus the auditor-facing compliance report.
type Posturer interface {
	Posture(ctx context.Context, tenantID, framework string) ([]platform.ControlState, error)
	// Coverage is the honesty layer — how much of the framework automated scanning actually assessed, so
	// the UI never presents a clean posture as "compliant".
	Coverage(ctx context.Context, tenantID, framework string) (grc.Coverage, error)
	Report(ctx context.Context, tenantID, framework string) (*grc.Report, error)
	Questionnaire(ctx context.Context, tenantID string) (*grc.Questionnaire, error)
	VAPTReport(ctx context.Context, tenantID string) (*grc.VAPTReport, error)
	// OSCAL emits the crosswalk's control coverage as a NIST OSCAL component-definition (GRC-tool-ingestible).
	OSCAL(ctx context.Context) ([]byte, error)
	// OSCALAssessmentResults emits the PER-TENANT findings-as-evidence OSCAL assessment-results (each control
	// satisfied/not-satisfied, gaps citing the finding that proved them) — the auditor-ingestible evidence doc.
	OSCALAssessmentResults(ctx context.Context, tenantID string) ([]byte, error)
	// Continuous compliance evidence: capture a timestamped posture snapshot onto the append-only timeline
	// (change+heartbeat-gated) and read the timeline back with a continuity summary — the SOC 2 Type II
	// "held across the window" artifact the point-in-time Report/EvidencePack can't give.
	CaptureEvidenceSnapshot(ctx context.Context, tenantID, framework string, minInterval time.Duration) (platform.ComplianceSnapshot, bool, error)
	EvidenceTimeline(ctx context.Context, tenantID, framework string) (grc.EvidenceTimeline, error)
	// Apply folds a finding's compliance annotation into the tenant's control-state posture (marks
	// each cited control a gap). The scan path calls this; the non-scan ingest paths (identity, SaaS,
	// runtime) must too, or their findings never reach the founder's compliance posture.
	Apply(ctx context.Context, tenantID string, f types.Finding) error
}

// IncidentOpener opens incidents for freshly-ingested high findings WITHOUT a resolve sweep (satisfied
// by *detect.Detector.OpenFor). The event-driven ingest paths (identity / SaaS) use it so a new threat
// raises a "new since last scan" incident immediately — the scan-pass Reconcile only sees scan output,
// never the ingested findings, so without this they'd never become incidents.
type IncidentOpener interface {
	OpenFor(ctx context.Context, tenantID string, current []types.Finding, attacked map[string]bool) (detect.Result, error)
}

// Sealer seals a raw secret (an OAuth token, an LLM API key) before it is persisted, and
// opens it back (satisfied by the secret vault — secret.Vault has both). When unset, the
// callback stores the value unsealed (dev only).
type Sealer interface {
	Seal(plaintext string) (string, error)
	Open(ref string) (string, error)
}

// handleApprovalDecide records a human's verdict on a pending action — the endpoint a
// Slack approve/reject button (or the web console) POSTs to.
func (d Deps) handleApprovalDecide(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.Desk == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("approvals not configured"))
		return
	}
	var body struct {
		Approver string         `json:"approver"`
		Approve  bool           `json:"approve"`
		Edit     map[string]any `json:"edit,omitempty"`
		// The third verdict: send it back for rework instead of destroying a proposal that was
		// mostly right (platform.ActChangesRequested).
		RequestChanges bool   `json:"request_changes,omitempty"`
		Feedback       string `json:"feedback,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad body: "+err.Error()))
		return
	}
	act, err := d.Desk.Decide(r.Context(), tenantID, r.PathValue("id"),
		hitl.Verdict{
			Approver: body.Approver, Approve: body.Approve, Edit: body.Edit,
			RequestChanges: body.RequestChanges, Feedback: body.Feedback,
		})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, act)
}

// handleConnectURL returns the provider OAuth consent URL. The state carries a SIGNED, expiring token
// for this (authenticated) tenant so the callback — which has no auth header — can attribute the
// connection without trusting an attacker-supplied tenant id (see oauthstate.go).
func (d Deps) handleConnectURL(w http.ResponseWriter, r *http.Request, tenantID string) {
	kind := r.PathValue("kind")
	conn, err := d.Connectors.Get(kind)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	// Fail loudly and EARLY when this deployment has no credentials for the provider. Without
	// this the authorize URL is built with an empty client_id and the customer is bounced onto
	// the provider's own error page, with nothing logged here to explain why.
	if !connector.IsConfigured(conn) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "the " + kind + " integration is not configured on this deployment — set " +
				connector.ConfigHint(conn) + " (see .env.example) and restart the platform",
			"reason": "connector_not_configured",
			"kind":   kind,
		})
		return
	}
	redirect := d.PublicURL + "/v1/connect/" + kind + "/callback"
	authorizeURL := conn.OAuthURL(d.signOAuthState(tenantID), redirect)
	// The guard above catches missing provider credentials; this catches the OTHER thing an authorize
	// URL needs, and its absence produced exactly the failure that guard's comment describes.
	//
	// With TSENGINE_PLATFORM_PUBLIC unset the redirect became the RELATIVE "/v1/connect/<kind>/callback".
	// Every OAuth provider requires an absolute redirect_uri, so the customer was sent to the provider
	// and bounced onto its error page, with nothing logged here to say why.
	//
	// Checked on the built URL rather than on a per-connector flag: the cloud connectors are console
	// and CloudFormation links that carry no redirect_uri and are unaffected, and a connector added
	// later is covered without anyone remembering to mark it.
	if err := redirectIsAbsolute(authorizeURL); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "this deployment has no public URL, so the " + kind + " sign-in link would send " +
				"customers to a redirect the provider will reject — set TSENGINE_PLATFORM_PUBLIC to " +
				"the address customers reach (e.g. https://app.yourdomain.com) and restart",
			"reason": "public_url_not_configured",
			"kind":   kind,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"authorize_url": authorizeURL})
}

// redirectIsAbsolute reports whether an authorize URL's redirect_uri (when it has one) is absolute.
// A connector whose flow carries no redirect_uri is fine by construction.
func redirectIsAbsolute(authorizeURL string) error {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return fmt.Errorf("authorize url is unparseable: %w", err)
	}
	r := u.Query().Get("redirect_uri")
	if r == "" {
		return nil
	}
	ru, err := url.Parse(r)
	if err != nil || ru.Scheme == "" || ru.Host == "" {
		return fmt.Errorf("redirect_uri %q is not absolute", r)
	}
	return nil
}

// handleConnectCallback completes OAuth: exchange the code, store the connection
// (token vaulted by the connector via SecretRef), then discover + scan the assets.
func (d Deps) handleConnectCallback(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	code, state := r.URL.Query().Get("code"), r.URL.Query().Get("state")
	if code == "" || state == "" {
		writeJSON(w, http.StatusBadRequest, errBody("missing code or state"))
		return
	}
	// Trust the tenant ONLY from a signature this server minted — never the raw query value. A forged or
	// expired state (cross-tenant connection-injection / OAuth login-CSRF) is rejected here.
	tenantID, ok := d.verifyOAuthState(state)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("invalid or expired state"))
		return
	}
	conn, err := d.Connectors.Get(kind)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	redirect := d.PublicURL + "/v1/connect/" + kind + "/callback"
	c, err := conn.Exchange(r.Context(), code, redirect)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errBody(err.Error()))
		return
	}
	c.TenantID = tenantID
	c.ID = d.newID("conn")
	// seal the raw token through the vault before it ever touches the store
	if d.Vault != nil {
		sealed, serr := d.Vault.Seal(c.SecretRef)
		if serr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("seal token: "+serr.Error()))
			return
		}
		c.SecretRef = sealed
	}
	if err := d.Store.PutConnection(r.Context(), c); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	// onboarding: discover + scan the freshly connected assets
	scanned := 0
	if d.Runner != nil {
		scanned, _ = d.Runner.DiscoverAndScan(r.Context(), c)
	}
	// Browser-facing OAuth redirect: land the founder back in the app on a "✓ connected, scanning
	// now" state instead of dumping a raw JSON blob in their browser (the post-connect "aha"). Only
	// when an app base is configured; otherwise keep the JSON (tests / non-browser callers).
	if d.AppURL != "" {
		dest := fmt.Sprintf("%s/assets?connected=%s&scanned=%d", strings.TrimRight(d.AppURL, "/"), url.QueryEscape(kind), scanned)
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"connection_id": c.ID, "assets_scanned": scanned})
}

func (d Deps) handlePosture(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("grc not configured"))
		return
	}
	cs, err := d.GRC.Posture(r.Context(), tenantID, r.PathValue("framework"))
	respond(w, cs, err)
}

// frameworkPosture is one framework's compliance summary (met/gap/total) — the shape the
// dashboard / compliance / reports pages actually use (they discard the full control-state list
// and just count it).
type frameworkPosture struct {
	Framework string `json:"framework"`
	Total     int    `json:"total"` // assessed controls (met+gap) — kept for back-compat
	Met       int    `json:"met"`
	Gap       int    `json:"gap"`
	// Coverage honesty fields — so the UI shows "X of Y assessed" and never reads a clean posture as
	// "compliant" (the no-false-compliant requirement).
	Assessable  int     `json:"assessable"`   // controls our tooling CAN assess for this framework
	NotAssessed int     `json:"not_assessed"` // assessable but no scan evidence yet
	CoveragePct float64 `json:"coverage_pct"` // assessed / assessable, 0..100
	Certifiable bool    `json:"certifiable"`  // ALWAYS false — automated scanning is not a certification
	Readiness   string  `json:"readiness"`    // honest status line, never "Compliant"
}

// handlePostureSummary (GET /v1/posture) returns every framework's posture summary the tenant has
// control state for, in ONE call. The dashboard, compliance, and reports pages each used to fan out
// 14 per-framework GET /v1/posture/{framework} requests — pulling the full control-state list only
// to count met-vs-gap. This collapses that to a single request returning just the counts (fewer
// round-trips AND less payload). `frameworks` is always a non-nil array so the UI can .map it
// safely (the nil-slice → JSON-null crash guard, TestGETEndpoints_NoNullArrays).
func (d Deps) handlePostureSummary(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("grc not configured"))
		return
	}
	out := []frameworkPosture{}
	for _, f := range grc.Frameworks {
		cov, err := d.GRC.Coverage(r.Context(), tenantID, f)
		if err != nil {
			respond(w, nil, err)
			return
		}
		if cov.AssessedControls == 0 {
			continue // a framework with no assessed control is omitted (consumers want only tracked ones)
		}
		out = append(out, frameworkPosture{
			Framework: f, Total: cov.AssessedControls, Met: cov.Met, Gap: cov.Gaps,
			Assessable: cov.AssessableControls, NotAssessed: cov.NotAssessed,
			CoveragePct: cov.AutomatedCoveragePct, Certifiable: cov.Certifiable, Readiness: cov.Readiness,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"frameworks": out})
}

// handleComplianceReport renders the auditor-facing compliance report for a framework —
// Markdown by default (the attachable deliverable), JSON with ?format=json.
func (d Deps) handleComplianceReport(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("grc not configured"))
		return
	}
	framework := r.PathValue("framework")
	if !grc.IsFramework(framework) {
		// An unknown framework must 404, never render a fabricated empty report titled with the
		// bogus key (grounding §10).
		writeJSON(w, http.StatusNotFound, errBody("unknown compliance framework: "+framework))
		return
	}
	rep, err := d.GRC.Report(r.Context(), tenantID, framework)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if r.URL.Query().Get("format") == "json" {
		writeJSON(w, http.StatusOK, rep)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = io.WriteString(w, grc.RenderMarkdown(rep))
}

// handleVAPTReport renders the customer-facing VAPT / pentest report — Markdown by default
// (the attachable deliverable an SMB hands a customer/insurer), JSON with ?format=json.
func (d Deps) handleVAPTReport(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("grc not configured"))
		return
	}
	rep, err := d.GRC.VAPTReport(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	// Same honesty as the per-engagement report: name the scope nothing has assessed, and do not
	// rate an unassessed estate. This is the WIDER of the two paths — the tenant-wide report covers
	// every asset, so a workspace that has connected assets but not yet scanned them is exactly the
	// case that would have read "every monitored asset is currently clean".
	rep.Untested = d.untestedScope(r.Context(), tenantID, rep.Scope)
	// Scanned-but-incompletely is a THIRD state, between assessed and not assessed. Without it a
	// tenant whose every target was scanned while half the tools died still closes with "every
	// monitored asset is currently clean".
	rep.PartiallyAssessed = d.partiallyAssessedScope(r.Context(), tenantID, rep.Scope)
	grc.Reassess(rep)
	switch r.URL.Query().Get("format") {
	case "json":
		writeJSON(w, http.StatusOK, rep)
		return
	case "html":
		// The print-ready deliverable — what the customer saves as PDF and forwards.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, grc.RenderVAPTHTML(rep))
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = io.WriteString(w, grc.RenderVAPTMarkdown(rep))
}

// handleQuestionnaire auto-answers the standardized security questionnaire from the
// tenant's live control state — JSON by default, Markdown with ?format=md (the
// attachable procurement deliverable).
func (d Deps) handleQuestionnaire(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("grc not configured"))
		return
	}
	q, err := d.GRC.Questionnaire(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if r.URL.Query().Get("format") == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = io.WriteString(w, grc.RenderQuestionnaireMarkdown(q))
		return
	}
	writeJSON(w, http.StatusOK, q)
}

func (d Deps) newID(prefix string) string {
	if d.NewID != nil {
		return prefix + "-" + d.NewID()
	}
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}
