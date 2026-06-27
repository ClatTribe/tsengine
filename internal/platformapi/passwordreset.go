package platformapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/email"
)

// mailer returns the configured transactional mailer, or a no-op when none is wired.
func (d Deps) mailer() email.Mailer {
	if d.Mailer != nil {
		return d.Mailer
	}
	return email.Noop{}
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// handleForgotPassword starts a password reset. It ALWAYS returns 200 with the same body
// regardless of whether the email exists (no account enumeration). When the account exists we
// mint a one-time token, store only its hash + a 1-hour expiry, and email a reset link. The raw
// token is never returned to the anonymous caller. With no mailer configured we log the link so a
// single-box operator can still complete a reset (the honest dev fallback; production wires SMTP).
func (d Deps) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	em := strings.ToLower(strings.TrimSpace(body.Email))
	ok := map[string]any{"ok": true, "message": "If an account exists for that email, a reset link is on its way."}
	if !strings.Contains(em, "@") {
		writeJSON(w, http.StatusOK, ok) // same response, no enumeration
		return
	}
	u, err := d.Store.GetUserByEmail(r.Context(), em)
	if err != nil {
		writeJSON(w, http.StatusOK, ok)
		return
	}
	token, err := authn.NewToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not start reset"))
		return
	}
	u.ResetTokenHash = sha256hex(token)
	u.ResetTokenExpires = time.Now().UTC().Add(time.Hour)
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	link := d.resetLink(em, token)
	if d.mailer().Configured() {
		if err := d.mailer().Send(r.Context(), em, "Reset your TensorShield password", resetEmailHTML(link)); err != nil {
			slog.Warn("[auth] reset email failed", "email", em, "err", err)
		}
	} else {
		// Dev / no-SMTP: surface the link to the operator's log, never to the anonymous response.
		slog.Info("[auth] password reset requested (no mailer configured) — share this link with the user", "email", em, "link", link)
	}
	writeJSON(w, http.StatusOK, ok)
}

// handleResetPassword completes a reset: verify the one-time token (constant-time) against the
// stored hash + expiry, set the new password, and clear the token + any forced-rotation flag.
func (d Deps) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email"`
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if len(body.NewPassword) < 8 {
		writeJSON(w, http.StatusBadRequest, errBody("password must be at least 8 characters"))
		return
	}
	em := strings.ToLower(strings.TrimSpace(body.Email))
	bad := errBody("this reset link is invalid or has expired — request a new one")
	u, err := d.Store.GetUserByEmail(r.Context(), em)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, bad)
		return
	}
	if u.ResetTokenHash == "" || time.Now().UTC().After(u.ResetTokenExpires) ||
		subtle.ConstantTimeCompare([]byte(sha256hex(strings.TrimSpace(body.Token))), []byte(u.ResetTokenHash)) != 1 {
		writeJSON(w, http.StatusBadRequest, bad)
		return
	}
	hash, err := authn.HashPassword(body.NewPassword)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not set password"))
		return
	}
	u.PasswordHash = hash
	u.ResetTokenHash = ""
	u.ResetTokenExpires = time.Time{}
	u.MustChangePassword = false
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Your password has been reset. You can sign in now."})
}

// resetLink builds the browser-facing reset URL. Falls back to a relative path when AppURL is unset.
func (d Deps) resetLink(em, token string) string {
	base := strings.TrimRight(d.AppURL, "/")
	return base + "/reset-password?token=" + url.QueryEscape(token) + "&email=" + url.QueryEscape(em)
}

func resetEmailHTML(link string) string {
	return `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:480px;margin:0 auto;color:#101828">
  <h2 style="font-size:18px;margin:0 0 12px">Reset your password</h2>
  <p style="font-size:14px;line-height:1.6;color:#475467">We received a request to reset your TensorShield password. Click below to choose a new one. This link expires in 1 hour.</p>
  <p style="margin:20px 0"><a href="` + link + `" style="display:inline-block;background:#4F46E5;color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:10px 18px;border-radius:10px">Reset password</a></p>
  <p style="font-size:12px;color:#98a2b3">If you didn't request this, you can safely ignore this email — your password won't change.</p>
</div>`
}
