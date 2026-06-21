package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Decider is the HITL desk surface the API needs (satisfied by *hitl.Desk).
type Decider interface {
	Decide(ctx context.Context, tenantID, actionID string, v hitl.Verdict) (platform.Action, error)
}

// Posturer is the GRC surface the API needs (satisfied by *grc.GRC): the raw control
// state plus the auditor-facing compliance report.
type Posturer interface {
	Posture(ctx context.Context, tenantID, framework string) ([]platform.ControlState, error)
	Report(ctx context.Context, tenantID, framework string) (*grc.Report, error)
	Questionnaire(ctx context.Context, tenantID string) (*grc.Questionnaire, error)
	VAPTReport(ctx context.Context, tenantID string) (*grc.VAPTReport, error)
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
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad body: "+err.Error()))
		return
	}
	act, err := d.Desk.Decide(r.Context(), tenantID, r.PathValue("id"),
		hitl.Verdict{Approver: body.Approver, Approve: body.Approve, Edit: body.Edit})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, act)
}

// handleConnectURL returns the provider OAuth consent URL. The CSRF state carries the
// tenant id so the callback (which has no auth header) can attribute the connection.
func (d Deps) handleConnectURL(w http.ResponseWriter, r *http.Request, tenantID string) {
	kind := r.PathValue("kind")
	conn, err := d.Connectors.Get(kind)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	redirect := d.PublicURL + "/v1/connect/" + kind + "/callback"
	writeJSON(w, http.StatusOK, map[string]string{"authorize_url": conn.OAuthURL(tenantID, redirect)})
}

// handleConnectCallback completes OAuth: exchange the code, store the connection
// (token vaulted by the connector via SecretRef), then discover + scan the assets.
func (d Deps) handleConnectCallback(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	code, tenantID := r.URL.Query().Get("code"), r.URL.Query().Get("state")
	if code == "" || tenantID == "" {
		writeJSON(w, http.StatusBadRequest, errBody("missing code or state"))
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

// handleComplianceReport renders the auditor-facing compliance report for a framework —
// Markdown by default (the attachable deliverable), JSON with ?format=json.
func (d Deps) handleComplianceReport(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("grc not configured"))
		return
	}
	rep, err := d.GRC.Report(r.Context(), tenantID, r.PathValue("framework"))
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
	if r.URL.Query().Get("format") == "json" {
		writeJSON(w, http.StatusOK, rep)
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
