package platformapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// sessionTTL is how long a sign-in lasts before re-authentication is required.
const sessionTTL = 30 * 24 * time.Hour

// bearer extracts the token from the Authorization header.
func bearer(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

// resolveSession returns the live session for the request's bearer token, if any.
func (d Deps) resolveSession(r *http.Request) (platform.Session, bool) {
	tok := bearer(r)
	if tok == "" {
		return platform.Session{}, false
	}
	s, err := d.Store.GetSession(r.Context(), tok)
	if err != nil || !time.Now().Before(s.ExpiresAt) {
		return platform.Session{}, false
	}
	return s, true
}

// sessionAuth gates a handler on a valid user session, passing the session through (for
// endpoints that need the acting user, e.g. /me, /logout, /invite).
func (d Deps) sessionAuth(h func(w http.ResponseWriter, r *http.Request, s platform.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := d.resolveSession(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		h(w, r, s)
	}
}

// issueSession mints + stores a session for a user and returns the auth payload the
// frontend persists (the session token doubles as the API bearer; tenant comes with it).
func (d Deps) issueSession(r *http.Request, u platform.User) (map[string]any, error) {
	tok, err := authn.NewToken()
	if err != nil {
		return nil, err
	}
	sess := platform.Session{Token: tok, UserID: u.ID, TenantID: u.TenantID, ExpiresAt: time.Now().Add(sessionTTL)}
	if err := d.Store.PutSession(r.Context(), sess); err != nil {
		return nil, err
	}
	u.PasswordHash = ""
	return map[string]any{"token": tok, "tenant": u.TenantID, "user": u}, nil
}

// handleSignup is the self-serve onboarding path: create a workspace (tenant) + its owner
// user, and sign them in. Email must be globally unique.
func (d Deps) handleSignup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Workspace string `json:"workspace"`
		Email     string `json:"email"`
		Password  string `json:"password"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	ws := strings.TrimSpace(body.Workspace)
	if ws == "" || !strings.Contains(email, "@") {
		writeJSON(w, http.StatusBadRequest, errBody("a workspace name and a valid email are required"))
		return
	}
	if _, err := d.Store.GetUserByEmail(r.Context(), email); err == nil {
		writeJSON(w, http.StatusConflict, errBody("an account with that email already exists"))
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	hash, err := authn.HashPassword(body.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("password must be at least 8 characters"))
		return
	}

	tenant := platform.Tenant{ID: d.newID("ten"), Name: ws, Plan: "free", CreatedAt: time.Now().UTC()}
	if err := d.Store.PutTenant(r.Context(), tenant); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	user := platform.User{
		ID: d.newID("usr"), TenantID: tenant.ID, Email: email, Name: strings.TrimSpace(body.Name),
		Role: platform.RoleOwner, PasswordHash: hash, CreatedAt: time.Now().UTC(),
	}
	if err := d.Store.PutUser(r.Context(), user); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	out, err := d.issueSession(r, user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// handleLogin verifies email + password and starts a session. The same error is returned
// for an unknown email and a bad password (no account enumeration).
func (d Deps) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	u, err := d.Store.GetUserByEmail(r.Context(), email)
	if err != nil || !authn.VerifyPassword(body.Password, u.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, errBody("invalid email or password"))
		return
	}
	out, err := d.issueSession(r, u)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleLogout revokes the current session.
func (d Deps) handleLogout(w http.ResponseWriter, r *http.Request, s platform.Session) {
	_ = d.Store.DeleteSession(r.Context(), s.Token)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleMe returns the signed-in user (password hash redacted).
func (d Deps) handleMe(w http.ResponseWriter, r *http.Request, s platform.Session) {
	u, err := d.Store.GetUser(r.Context(), s.UserID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("user not found"))
		return
	}
	u.PasswordHash = ""
	writeJSON(w, http.StatusOK, u)
}

// handleTeam lists the tenant's members, oldest first, with password hashes redacted.
func (d Deps) handleTeam(w http.ResponseWriter, r *http.Request, s platform.Session) {
	users, err := d.Store.ListUsers(r.Context(), s.TenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	sort.Slice(users, func(i, j int) bool { return users[i].CreatedAt.Before(users[j].CreatedAt) })
	for i := range users {
		users[i].PasswordHash = ""
	}
	writeJSON(w, http.StatusOK, users)
}

// handleInvite lets a workspace OWNER add a teammate. Without email infrastructure, the
// account is provisioned with a one-time temporary password returned to the owner to
// share out-of-band; the teammate signs in with it (changing it is future work).
func (d Deps) handleInvite(w http.ResponseWriter, r *http.Request, s platform.Session) {
	actor, err := d.Store.GetUser(r.Context(), s.UserID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
		return
	}
	if actor.Role != platform.RoleOwner {
		writeJSON(w, http.StatusForbidden, errBody("only the workspace owner can invite teammates"))
		return
	}
	var body struct {
		Email string `json:"email"`
		Name  string `json:"name"`
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
	if _, err := d.Store.GetUserByEmail(r.Context(), email); err == nil {
		writeJSON(w, http.StatusConflict, errBody("a user with that email already exists"))
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	tok, err := authn.NewToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	temp := tok[:14] // a usable one-time password (≥8 chars)
	hash, err := authn.HashPassword(temp)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	u := platform.User{
		ID: d.newID("usr"), TenantID: s.TenantID, Email: email, Name: strings.TrimSpace(body.Name),
		Role: platform.RoleMember, PasswordHash: hash, CreatedAt: time.Now().UTC(),
	}
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	u.PasswordHash = ""
	writeJSON(w, http.StatusCreated, map[string]any{"user": u, "temp_password": temp})
}
