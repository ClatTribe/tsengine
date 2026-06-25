package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// operator.go is the CROSS-TENANT operator auth + console. An operator is a practitioner (the MSP's
// expert or our managed delivery expert) who works the human-in-the-loop across a book of client
// tenants. This is a DELIBERATELY SEPARATE auth namespace from the tenant User/Session: operator
// sessions live in their own store map, are validated by their own middleware, and grant ONLY the
// cross-tenant practitioner queue (read-only aggregation, scoped to the tenants whose roster names the
// operator). A tenant session can never reach these endpoints and an operator session can never reach
// a tenant endpoint — so tenant isolation (§18.2 inv. 2) is untouched. Operator ACCOUNTS are
// provisioned by the deployment operator (platform token), not self-serve.

// operatorAuth validates an operator session bearer token and passes the operator to the handler.
func (d Deps) operatorAuth(h func(w http.ResponseWriter, r *http.Request, op platform.Operator)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		sess, err := d.Store.GetOperatorSession(r.Context(), tok)
		if err != nil || sess.ExpiresAt.Before(time.Now()) {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		op, err := d.Store.GetOperator(r.Context(), sess.OperatorID)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		h(w, r, op)
	}
}

// handleCreateOperator provisions an operator account. Platform-token gated (operator accounts are
// provisioned by the deployment operator, not self-serve). Email must be unique among operators.
func (d Deps) handleCreateOperator(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Firm     string `json:"firm"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if !strings.Contains(email, "@") {
		writeJSON(w, http.StatusBadRequest, errBody("a valid email is required"))
		return
	}
	if len(body.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, errBody("password must be at least 8 characters"))
		return
	}
	if _, err := d.Store.GetOperatorByEmail(r.Context(), email); err == nil {
		writeJSON(w, http.StatusConflict, errBody("an operator with that email already exists"))
		return
	}
	hash, err := authn.HashPassword(body.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	id := "op-" + email
	if d.NewID != nil {
		id = "op-" + d.NewID()
	}
	op := platform.Operator{ID: id, Email: email, Name: strings.TrimSpace(body.Name), Firm: strings.TrimSpace(body.Firm), PasswordHash: hash, CreatedAt: time.Now().UTC()}
	if err := d.Store.PutOperator(r.Context(), op); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	op.PasswordHash = ""
	writeJSON(w, http.StatusOK, op)
}

// handleOperatorLogin verifies email + password and starts an operator session.
func (d Deps) handleOperatorLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	op, err := d.Store.GetOperatorByEmail(r.Context(), strings.TrimSpace(body.Email))
	if err != nil || !authn.VerifyPassword(body.Password, op.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, errBody("invalid email or password"))
		return
	}
	tok, err := authn.NewToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if err := d.Store.PutOperatorSession(r.Context(), platform.OperatorSession{Token: tok, OperatorID: op.ID, ExpiresAt: time.Now().Add(sessionTTL)}); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	op.PasswordHash = ""
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "operator": op})
}

func (d Deps) handleOperatorMe(w http.ResponseWriter, _ *http.Request, op platform.Operator) {
	op.PasswordHash = ""
	writeJSON(w, http.StatusOK, op)
}

func (d Deps) handleOperatorLogout(w http.ResponseWriter, r *http.Request, _ platform.Operator) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	_ = d.Store.DeleteOperatorSession(r.Context(), tok)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleOperatorQueue is the operator console's cross-tenant work queue — scoped to the AUTHENTICATED
// operator's email (they only ever see their own book). Read-only aggregation; isolation preserved.
func (d Deps) handleOperatorQueue(w http.ResponseWriter, r *http.Request, op platform.Operator) {
	resp, err := d.practitionerQueue(r, op.Email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
