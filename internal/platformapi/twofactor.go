package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/totp"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// twofactor.go is the second sign-in factor: an authenticator app (TOTP, RFC 6238) plus single-use
// recovery codes.
//
// The design is a set of refusals, because a second factor that can be stepped around is worse than
// none — it is the control a customer's security questionnaire asks about, and answering "yes" for a
// login that a stolen password still opens would be the overclaim this product is built against.
//
//   - A correct password on an account with 2FA yields a HALF-session (Session.MFAPending), never a
//     usable one. resolveSession refuses it everywhere, so there is no endpoint it opens by accident;
//     the only thing it can do is be redeemed at /v1/auth/2fa/verify, which deletes it.
//   - Five wrong codes burn the half-session. Guessing needs the password again for every five tries.
//   - A code is accepted once: the matched time step is stored and nothing at or below it is
//     accepted again, so a code read over a shoulder or from a proxy log does not work twice.
//   - 2FA is ON only after the user has proved the authenticator works (a code from it verified).
//     Turning it on from setup alone would lock out anyone whose scan did not take.
//   - The seed is SEALED by the vault before it touches the store (§18.2 inv. 6). With no vault the
//     setup is refused rather than storing a seed in plaintext.
//   - Turning it on signs out every OTHER session: a session established before the second factor
//     existed must not outlive it. Turning it off or regenerating codes needs the password AND a
//     current code, so a borrowed laptop with an open session cannot remove the protection.
//   - Password reset does NOT turn it off. Reset proves control of the mailbox, and the second factor
//     exists precisely for the day the mailbox is the thing that was taken.

// pendingTTL bounds how long a password-correct, second-factor-owed sign-in stays redeemable.
const pendingTTL = 5 * time.Minute

// maxMFAAttempts is how many wrong codes a half-session survives.
const maxMFAAttempts = 5

// totpIssuer is the name an authenticator app shows beside the code.
const totpIssuer = "TensorShield"

// startSecondFactor replaces the session a correct password would have earned with a half-session.
func (d Deps) startSecondFactor(w http.ResponseWriter, r *http.Request, u platform.User) {
	tok, err := authn.NewToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not start sign-in"))
		return
	}
	sess := platform.Session{Token: tok, UserID: u.ID, TenantID: u.TenantID,
		ExpiresAt: time.Now().Add(pendingTTL), MFAPending: true}
	if err := d.Store.PutSession(r.Context(), sess); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	// No "token" key: a client that only knows the old shape must fail to sign in, not succeed with a
	// half-session it does not know is one.
	writeJSON(w, http.StatusOK, map[string]any{"two_factor_required": true, "challenge": tok})
}

// handleTwoFactorVerify redeems a half-session with a current code or a recovery code.
func (d Deps) handleTwoFactorVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Challenge    string `json:"challenge"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	expired := errCode("this sign-in has expired — enter your email and password again", "two_factor_expired")
	s, err := d.Store.GetSession(r.Context(), strings.TrimSpace(body.Challenge))
	if err != nil || !s.MFAPending || !time.Now().Before(s.ExpiresAt) {
		writeJSON(w, http.StatusUnauthorized, expired)
		return
	}
	u, err := d.Store.GetUser(r.Context(), s.UserID)
	if err != nil || !u.TwoFactorEnabled {
		_ = d.Store.DeleteSession(r.Context(), s.Token)
		writeJSON(w, http.StatusUnauthorized, expired)
		return
	}

	usedRecovery := false
	switch {
	case strings.TrimSpace(body.RecoveryCode) != "":
		rest, ok := totp.ConsumeRecovery(u.RecoveryHashes, body.RecoveryCode)
		if ok {
			u.RecoveryHashes, usedRecovery = rest, true
		} else {
			d.refuseSecondFactor(w, r, s, "that recovery code is not valid, or has already been used")
			return
		}
	default:
		step, ok, verr := d.checkTOTP(u, body.Code, time.Now())
		if verr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not check the code"))
			return
		}
		if !ok {
			d.refuseSecondFactor(w, r, s, "that code is not right — check the time on your phone and try the current one")
			return
		}
		u.TOTPLastStep = step
	}
	// Persist the consumed code BEFORE issuing the session: if the write fails, nothing was granted and
	// the code can still be used, rather than a session existing on a code that stays valid.
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	_ = d.Store.DeleteSession(r.Context(), s.Token)
	out, err := d.issueSession(r, u)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if usedRecovery {
		out["recovery_codes_remaining"] = len(u.RecoveryHashes)
		d.record("two-factor recovery code used", u, map[string]any{"remaining": len(u.RecoveryHashes)})
	}
	writeJSON(w, http.StatusOK, out)
}

// refuseSecondFactor counts a wrong code against the half-session and burns it at the limit.
func (d Deps) refuseSecondFactor(w http.ResponseWriter, r *http.Request, s platform.Session, msg string) {
	s.MFAAttempts++
	if s.MFAAttempts >= maxMFAAttempts {
		_ = d.Store.DeleteSession(r.Context(), s.Token)
		writeJSON(w, http.StatusUnauthorized, errCode(
			"too many wrong codes — enter your email and password again", "two_factor_locked"))
		return
	}
	_ = d.Store.PutSession(r.Context(), s)
	writeJSON(w, http.StatusUnauthorized, errCode(msg, "two_factor_invalid"))
}

// checkTOTP verifies a code against the user's CONFIRMED seed and refuses a replayed step.
func (d Deps) checkTOTP(u platform.User, code string, now time.Time) (int64, bool, error) {
	return d.checkSealedTOTP(u.TOTPSecretRef, u.TOTPLastStep, code, now)
}

// checkSealedTOTP is the one code check both account kinds use: open the sealed seed, verify, and
// refuse any step at or below the last one accepted.
func (d Deps) checkSealedTOTP(secretRef string, lastStep int64, code string, now time.Time) (int64, bool, error) {
	if secretRef == "" || d.Vault == nil {
		return 0, false, nil
	}
	secret, err := d.Vault.Open(secretRef)
	if err != nil {
		return 0, false, err
	}
	step, ok := totp.Verify(secret, code, now)
	if !ok || step <= lastStep {
		return 0, false, nil
	}
	return step, true, nil
}

// errNoVault is why setup refuses on a deployment that cannot seal a seed.
var errNoVault = errors.New("two-factor sign-in needs TSENGINE_SECRET_KEY set on the platform, so the authenticator seed can be encrypted at rest")

// handleTwoFactorSetup starts enrolment: a fresh seed, sealed and held as PENDING until confirmed.
func (d Deps) handleTwoFactorSetup(w http.ResponseWriter, r *http.Request, s platform.Session) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	u, ok := d.reauthUser(w, r, s, body.Password)
	if !ok {
		return
	}
	if u.TwoFactorEnabled {
		writeJSON(w, http.StatusConflict, errBody("two-factor sign-in is already on — turn it off first to move it to a new device"))
		return
	}
	if d.Vault == nil {
		writeJSON(w, http.StatusNotImplemented, errCode(errNoVault.Error(), "no_vault"))
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not create a secret"))
		return
	}
	ref, err := d.Vault.Seal(secret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not store the secret"))
		return
	}
	u.TOTPPendingRef = ref
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	// The seed is returned ONCE, here, for the authenticator to import; it is never readable again.
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret,
		"uri":    totp.URI(totpIssuer, u.Email, secret),
		"detail": "Add this key to your authenticator app, then enter the 6-digit code it shows to turn two-factor sign-in on.",
	})
}

// handleTwoFactorEnable confirms the pending seed with a code from it, turns 2FA on, issues recovery
// codes and signs out every other session.
func (d Deps) handleTwoFactorEnable(w http.ResponseWriter, r *http.Request, s platform.Session) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	u, err := d.Store.GetUser(r.Context(), s.UserID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
		return
	}
	if u.TwoFactorEnabled {
		writeJSON(w, http.StatusConflict, errBody("two-factor sign-in is already on"))
		return
	}
	if u.TOTPPendingRef == "" || d.Vault == nil {
		writeJSON(w, http.StatusBadRequest, errBody("start setup first — there is no authenticator waiting to be confirmed"))
		return
	}
	secret, err := d.Vault.Open(u.TOTPPendingRef)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not read the pending secret"))
		return
	}
	step, ok := totp.Verify(secret, body.Code, time.Now())
	if !ok {
		writeJSON(w, http.StatusBadRequest, errCode(
			"that code does not match — two-factor sign-in is NOT on yet. Check the time on your phone and try the current code",
			"two_factor_invalid"))
		return
	}
	plain, hashes, err := totp.NewRecoveryCodes()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not create recovery codes"))
		return
	}
	u.TOTPSecretRef, u.TOTPPendingRef = u.TOTPPendingRef, ""
	u.TOTPLastStep = step
	u.RecoveryHashes = hashes
	u.TwoFactorEnabled = true
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	revoked := d.revokeOtherSessions(r.Context(), u.ID, s)
	d.record("two-factor sign-in turned on", u, nil)
	out := map[string]any{
		"ok": true, "recovery_codes": plain, "other_sessions_signed_out": revoked,
		"detail": "Two-factor sign-in is on. Save these recovery codes somewhere safe — each works once, " +
			"and they are the only way in if you lose your phone. They will not be shown again.",
	}
	if !revoked {
		out["warning"] = "Two-factor sign-in is on, but we could not sign out your other sessions. A session " +
			"opened before this change may still be active elsewhere. Try again from Settings."
	}
	writeJSON(w, http.StatusOK, out)
}

// handleTwoFactorDisable turns 2FA off. It needs the password AND a current code (or a recovery code):
// an open session alone must not be able to remove the protection.
func (d Deps) handleTwoFactorDisable(w http.ResponseWriter, r *http.Request, s platform.Session) {
	u, ok := d.reauthSecondFactor(w, r, s)
	if !ok {
		return
	}
	u.TwoFactorEnabled = false
	u.TOTPSecretRef, u.TOTPPendingRef, u.TOTPLastStep, u.RecoveryHashes = "", "", 0, nil
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	d.record("two-factor sign-in turned off", u, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRecoveryCodes replaces the recovery codes (the old set stops working). Password + code.
func (d Deps) handleRecoveryCodes(w http.ResponseWriter, r *http.Request, s platform.Session) {
	u, ok := d.reauthSecondFactor(w, r, s)
	if !ok {
		return
	}
	plain, hashes, err := totp.NewRecoveryCodes()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not create recovery codes"))
		return
	}
	u.RecoveryHashes = hashes
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	d.record("two-factor recovery codes replaced", u, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery_codes": plain,
		"detail": "Your old recovery codes no longer work. Save these — they will not be shown again."})
}

// reauthUser checks the password of the signed-in user (the gate for enrolling a new authenticator).
func (d Deps) reauthUser(w http.ResponseWriter, r *http.Request, s platform.Session, password string) (platform.User, bool) {
	u, err := d.Store.GetUser(r.Context(), s.UserID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
		return u, false
	}
	if !authn.VerifyPassword(password, u.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, errBody("password is incorrect"))
		return u, false
	}
	return u, true
}

// reauthSecondFactor checks the password AND a current code or recovery code, consuming whichever was
// used. It is the gate for weakening or rotating the protection.
func (d Deps) reauthSecondFactor(w http.ResponseWriter, r *http.Request, s platform.Session) (platform.User, bool) {
	var body struct {
		Password     string `json:"password"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return platform.User{}, false
	}
	u, ok := d.reauthUser(w, r, s, body.Password)
	if !ok {
		return u, false
	}
	if !u.TwoFactorEnabled {
		writeJSON(w, http.StatusConflict, errBody("two-factor sign-in is not on"))
		return u, false
	}
	if strings.TrimSpace(body.RecoveryCode) != "" {
		rest, ok := totp.ConsumeRecovery(u.RecoveryHashes, body.RecoveryCode)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, errCode("that recovery code is not valid, or has already been used", "two_factor_invalid"))
			return u, false
		}
		u.RecoveryHashes = rest
		return u, true
	}
	step, ok, err := d.checkTOTP(u, body.Code, time.Now())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not check the code"))
		return u, false
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errCode("that code is not right", "two_factor_invalid"))
		return u, false
	}
	u.TOTPLastStep = step
	return u, true
}

// revokeOtherSessions signs out every session of the user except the caller's, reporting whether the
// wipe landed (handlePassword's reasoning: a failed revocation is reported, never swallowed).
func (d Deps) revokeOtherSessions(ctx context.Context, userID string, keep platform.Session) bool {
	if err := d.Store.DeleteSessionsForUser(ctx, userID); err != nil {
		return false
	}
	_ = d.Store.PutSession(ctx, keep)
	return true
}

// record writes a signed ledger entry for a change to how an account signs in.
func (d Deps) record(what string, u platform.User, extra map[string]any) {
	if d.Recorder == nil {
		return
	}
	payload := map[string]any{"tenant_id": u.TenantID, "user_id": u.ID, "email": u.Email}
	for k, v := range extra {
		payload[k] = v
	}
	d.Recorder.Record(what, "auth", payload, "account security")
}
