package platformapi

import (
	"encoding/json"
	"errors"
	"log/slog"
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
		Source    string `json:"source"` // optional attribution: the ?ref= the signup arrived with
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

	tenant := platform.Tenant{ID: d.newID("ten"), Name: ws, Plan: "free", CreatedAt: time.Now().UTC(), Source: normalizeSource(body.Source)}
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
	// A signup is the warmest lead the site produces and it reached nobody: the demo form, the scan
	// page and the SOC 2 assessment all notify sales, while the person who went one step further
	// and created a workspace was visible only to whoever queried the store. Same delivery path,
	// same gate (TSENGINE_SALES_EMAIL + a configured Mailer, else a log line), source tagged so the
	// nurture sequence can be keyed to the trigger — and to the door they came through.
	leadSource := "signup"
	if tenant.Source != "" {
		leadSource += ":" + tenant.Source
	}
	d.notifySalesLead(r.Context(), user.Name, email, ws, leadSource, "")
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

// handlePassword changes the signed-in user's password: verify the current one, store the
// new one, and clear MustChangePassword. This is the forced-rotation path for an invited
// member (their temp password is known to the owner who issued it) and a general
// change-password for anyone. Same session stays valid.
func (d Deps) handlePassword(w http.ResponseWriter, r *http.Request, s platform.Session) {
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	u, err := d.Store.GetUser(r.Context(), s.UserID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
		return
	}
	if !authn.VerifyPassword(body.CurrentPassword, u.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, errBody("current password is incorrect"))
		return
	}
	if body.NewPassword == body.CurrentPassword {
		writeJSON(w, http.StatusBadRequest, errBody("the new password must differ from the current one"))
		return
	}
	hash, err := authn.HashPassword(body.NewPassword)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("password must be at least 8 characters"))
		return
	}
	u.PasswordHash = hash
	u.MustChangePassword = false
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	// Revoke the user's OTHER sessions, keeping the caller signed in: wipe all, then re-put the
	// current one. The password change is already persisted and must NOT be rolled back — a user who
	// cannot change their password at all is worse off than one whose old sessions linger.
	//
	// BUT THE FAILURE IS REPORTED, because this is the security-relevant half. The reason someone
	// changes a password is usually that they believe the old one is compromised, and "evict any
	// stolen token" is what this call is for. Swallowing its error answered {"ok":true} to exactly
	// that person while the attacker's session stayed valid — a silent failure of the one thing they
	// came here to do.
	revoked := true
	if err := d.Store.DeleteSessionsForUser(r.Context(), u.ID); err != nil {
		revoked = false
	} else if err := d.Store.PutSession(r.Context(), s); err != nil {
		// The wipe DID land, so every other session is gone and so is this one. The caller is signed
		// out rather than exposed, which is the safe direction — but they are told, because
		// otherwise their next request 401s for no reason they can see.
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "sessions_revoked": true, "signed_out": true,
			"detail": "Your password was changed and all sessions were signed out, including this " +
				"one. Sign in again with the new password.",
		})
		return
	}
	if !revoked {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "sessions_revoked": false,
			"detail": "Your password was changed, but we could not sign out your other sessions. If " +
				"you are changing it because it may have been stolen, that matters: an existing " +
				"session elsewhere may still be active. Try again, and contact support if it persists.",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sessions_revoked": true})
}

// handleInvite lets a workspace OWNER add a teammate. Without email infrastructure, the
// account is provisioned with a one-time temporary password returned to the owner to
// share out-of-band; the teammate signs in with it, then is forced to set their own
// (MustChangePassword) before the app unlocks.
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
		Role  string `json:"role"` // "" | member | auditor — never owner
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
	role := platform.RoleMember
	switch strings.ToLower(strings.TrimSpace(body.Role)) {
	case "", platform.RoleMember:
	case platform.RoleAuditor:
		role = platform.RoleAuditor
	default:
		// Owner is not an invitable role — a workspace has the one that created it — and an
		// unknown role must not silently become a member seat.
		writeJSON(w, http.StatusBadRequest, errBody("role must be member or auditor"))
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
		Role: role, PasswordHash: hash, CreatedAt: time.Now().UTC(),
		MustChangePassword: true, // the temp password is the owner's; force the member to set their own
	}
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	u.PasswordHash = ""

	// Deliver the credential. SMTP was wired for password reset but invites never used it, so
	// every invite fell back to the owner relaying a password over chat — the weakest link in
	// onboarding. When mail works we send it straight to the invitee and DO NOT return it, so
	// the credential never transits the owner's browser or the API logs. With no mailer we keep
	// the previous behaviour and say plainly that manual relay is required.
	if d.mailerConfigured() {
		if err := d.mailer().Send(r.Context(), email,
			"You've been invited to TensorShield", inviteEmailHTML(d.PublicURL, email, temp)); err != nil {
			// The account already exists, so failing the request would strand it. Fall back to
			// returning the credential, and say delivery failed.
			slog.Warn("[auth] invite email failed — returning the temp password for manual relay",
				"email", email, "err", err)
			writeJSON(w, http.StatusCreated, map[string]any{
				"user": u, "temp_password": temp, "emailed": false,
				"note": "invite email failed to send — share this one-time password securely; it must be changed at first login",
			})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"user": u, "emailed": true,
			"note": "an invite email with a one-time password was sent; it must be changed at first login",
		})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"user": u, "temp_password": temp, "emailed": false,
		"note": "no SMTP configured — share this one-time password securely; it must be changed at first login",
	})
}

// inviteEmailHTML renders the invite. The one-time password it carries must be changed at first
// login (User.MustChangePassword), which is what keeps a mailed credential acceptable.
func inviteEmailHTML(publicURL, addr, temp string) string {
	login := strings.TrimSuffix(publicURL, "/") + "/login"
	return `<p>You've been invited to TensorShield.</p>` +
		`<p>Sign in at <a href="` + login + `">` + login + `</a> with:</p>` +
		`<p><b>Email:</b> ` + addr + `<br><b>One-time password:</b> <code>` + temp + `</code></p>` +
		`<p>You'll be asked to set your own password immediately after signing in.</p>` +
		`<p>If you weren't expecting this invitation, you can ignore this email.</p>`
}

// normalizeSource bounds an attribution tag so it can be COUNTED: lower-case, trimmed, only
// [a-z0-9._-], at most 64 characters. Anything else is dropped to "" (direct/unknown) rather than
// stored raw — a free-text field that accepts anything is one nobody can group by, and an
// attacker-controlled query string is not something to persist verbatim on every tenant record.
func normalizeSource(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if len(raw) > 64 {
		raw = raw[:64]
	}
	for _, r := range raw {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return ""
		}
	}
	return raw
}
