package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/totp"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// operator_twofactor.go is two-factor sign-in for the OPERATOR namespace (§18.5) — the MSP's or our
// managed practitioner, whose one credential reaches every client tenant on their roster and can
// decide risks, publish policies, sign off pentests and attest controls on those clients' behalf. It
// is the more valuable credential to protect than any single tenant seat.
//
// Same rules as the tenant flow (twofactor.go), applied to the separate store maps — the operator and
// tenant namespaces never share a session, so they do not share a half-session either:
//   - a correct password with 2FA on yields a half-session operatorAuth refuses everywhere;
//   - five wrong codes burn it; a code works once; on only after a code from the new authenticator
//     verifies; seed sealed or setup refused; turning it on signs out every other operator session;
//     off / new recovery codes need password AND code.
//
// Plus one rule the tenant side does not have yet: a DEPLOYMENT may require it
// (TSENGINE_OPERATOR_REQUIRE_2FA=1 → Deps.OperatorRequire2FA). An operator without it may then sign in
// and reach ONLY what enrolment needs (who am I, sign out, the 2FA endpoints); everything that touches
// a client answers 403 two_factor_setup_required. Opt-in, because switching it on with no notice would
// lock existing operators out of their book mid-day.

// operatorMayReachWithout2FA lists what an operator who has not enrolled may still reach when the
// deployment requires it: enough to see who they are, leave, and enrol.
func operatorMayReachWithout2FA(path string) bool {
	return path == "/v1/operator/me" || path == "/v1/operator/logout" || strings.HasPrefix(path, "/v1/operator/2fa/")
}

// startOperatorSecondFactor replaces the operator session a correct password would earn with a
// half-session.
func (d Deps) startOperatorSecondFactor(w http.ResponseWriter, r *http.Request, op platform.Operator) {
	tok, err := authn.NewToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not start sign-in"))
		return
	}
	if err := d.Store.PutOperatorSession(r.Context(), platform.OperatorSession{
		Token: tok, OperatorID: op.ID, ExpiresAt: time.Now().Add(pendingTTL), MFAPending: true,
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"two_factor_required": true, "challenge": tok})
}

// handleOperatorTwoFactorVerify redeems an operator half-session with a current code or a recovery code.
func (d Deps) handleOperatorTwoFactorVerify(w http.ResponseWriter, r *http.Request) {
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
	s, err := d.Store.GetOperatorSession(r.Context(), strings.TrimSpace(body.Challenge))
	if err != nil || !s.MFAPending || !time.Now().Before(s.ExpiresAt) {
		writeJSON(w, http.StatusUnauthorized, expired)
		return
	}
	op, err := d.Store.GetOperator(r.Context(), s.OperatorID)
	if err != nil || !op.TwoFactorEnabled {
		_ = d.Store.DeleteOperatorSession(r.Context(), s.Token)
		writeJSON(w, http.StatusUnauthorized, expired)
		return
	}
	refuse := func(msg string) {
		s.MFAAttempts++
		if s.MFAAttempts >= maxMFAAttempts {
			_ = d.Store.DeleteOperatorSession(r.Context(), s.Token)
			writeJSON(w, http.StatusUnauthorized, errCode("too many wrong codes — enter your email and password again", "two_factor_locked"))
			return
		}
		_ = d.Store.PutOperatorSession(r.Context(), s)
		writeJSON(w, http.StatusUnauthorized, errCode(msg, "two_factor_invalid"))
	}
	usedRecovery := false
	if strings.TrimSpace(body.RecoveryCode) != "" {
		rest, ok := totp.ConsumeRecovery(op.RecoveryHashes, body.RecoveryCode)
		if !ok {
			refuse("that recovery code is not valid, or has already been used")
			return
		}
		op.RecoveryHashes, usedRecovery = rest, true
	} else {
		step, ok, verr := d.checkSealedTOTP(op.TOTPSecretRef, op.TOTPLastStep, body.Code, time.Now())
		if verr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not check the code"))
			return
		}
		if !ok {
			refuse("that code is not right — check the time on your phone and try the current one")
			return
		}
		op.TOTPLastStep = step
	}
	if err := d.Store.PutOperator(r.Context(), op); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	_ = d.Store.DeleteOperatorSession(r.Context(), s.Token)
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
	out := map[string]any{"token": tok, "operator": op}
	if usedRecovery {
		out["recovery_codes_remaining"] = len(op.RecoveryHashes)
		d.recordOperator("operator two-factor recovery code used", op)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleOperatorTwoFactorSetup starts enrolment (password required).
func (d Deps) handleOperatorTwoFactorSetup(w http.ResponseWriter, r *http.Request, op platform.Operator) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if !authn.VerifyPassword(body.Password, op.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, errBody("password is incorrect"))
		return
	}
	if op.TwoFactorEnabled {
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
	op.TOTPPendingRef = ref
	if err := d.Store.PutOperator(r.Context(), op); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret, "uri": totp.URI(totpIssuer+" operator", op.Email, secret),
		"detail": "Add this key to your authenticator app, then enter the 6-digit code it shows to turn two-factor sign-in on.",
	})
}

// handleOperatorTwoFactorEnable confirms the pending seed, turns 2FA on, issues recovery codes and
// signs out every other operator session.
func (d Deps) handleOperatorTwoFactorEnable(w http.ResponseWriter, r *http.Request, op platform.Operator) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if op.TwoFactorEnabled {
		writeJSON(w, http.StatusConflict, errBody("two-factor sign-in is already on"))
		return
	}
	if op.TOTPPendingRef == "" || d.Vault == nil {
		writeJSON(w, http.StatusBadRequest, errBody("start setup first — there is no authenticator waiting to be confirmed"))
		return
	}
	secret, err := d.Vault.Open(op.TOTPPendingRef)
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
	op.TOTPSecretRef, op.TOTPPendingRef = op.TOTPPendingRef, ""
	op.TOTPLastStep, op.RecoveryHashes, op.TwoFactorEnabled = step, hashes, true
	if err := d.Store.PutOperator(r.Context(), op); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	// Keep the caller signed in: read their session BEFORE the wipe, then put it back unchanged.
	revoked := false
	if cur, cerr := d.Store.GetOperatorSession(r.Context(), bearer(r)); cerr == nil {
		if err := d.Store.DeleteOperatorSessionsFor(r.Context(), op.ID); err == nil {
			_ = d.Store.PutOperatorSession(r.Context(), cur)
			revoked = true
		}
	}
	d.recordOperator("operator two-factor sign-in turned on", op)
	out := map[string]any{"ok": true, "recovery_codes": plain, "other_sessions_signed_out": revoked,
		"detail": "Two-factor sign-in is on. Save these recovery codes — each works once, and they will not be shown again."}
	if !revoked {
		out["warning"] = "Two-factor sign-in is on, but we could not sign out your other sessions. A session opened " +
			"before this change may still be active elsewhere."
	}
	writeJSON(w, http.StatusOK, out)
}

// handleOperatorTwoFactorDisable turns it off (password AND code). Refused while the deployment
// requires it: the operator would be locked out of their book the moment they did it.
func (d Deps) handleOperatorTwoFactorDisable(w http.ResponseWriter, r *http.Request, op platform.Operator) {
	if d.OperatorRequire2FA {
		writeJSON(w, http.StatusForbidden, errCode(
			"this deployment requires two-factor sign-in for operators — move it to a new device by replacing it, not turning it off",
			"two_factor_required_by_policy"))
		return
	}
	op, ok := d.reauthOperatorSecondFactor(w, r, op)
	if !ok {
		return
	}
	op.TwoFactorEnabled = false
	op.TOTPSecretRef, op.TOTPPendingRef, op.TOTPLastStep, op.RecoveryHashes = "", "", 0, nil
	if err := d.Store.PutOperator(r.Context(), op); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	d.recordOperator("operator two-factor sign-in turned off", op)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleOperatorRecoveryCodes replaces the operator's recovery codes (password AND code).
func (d Deps) handleOperatorRecoveryCodes(w http.ResponseWriter, r *http.Request, op platform.Operator) {
	op, ok := d.reauthOperatorSecondFactor(w, r, op)
	if !ok {
		return
	}
	plain, hashes, err := totp.NewRecoveryCodes()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not create recovery codes"))
		return
	}
	op.RecoveryHashes = hashes
	if err := d.Store.PutOperator(r.Context(), op); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	d.recordOperator("operator two-factor recovery codes replaced", op)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery_codes": plain,
		"detail": "Your old recovery codes no longer work. Save these — they will not be shown again."})
}

// reauthOperatorSecondFactor checks the password AND a current code or recovery code.
func (d Deps) reauthOperatorSecondFactor(w http.ResponseWriter, r *http.Request, op platform.Operator) (platform.Operator, bool) {
	var body struct {
		Password     string `json:"password"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return op, false
	}
	if !authn.VerifyPassword(body.Password, op.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, errBody("password is incorrect"))
		return op, false
	}
	if !op.TwoFactorEnabled {
		writeJSON(w, http.StatusConflict, errBody("two-factor sign-in is not on"))
		return op, false
	}
	if strings.TrimSpace(body.RecoveryCode) != "" {
		rest, ok := totp.ConsumeRecovery(op.RecoveryHashes, body.RecoveryCode)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, errCode("that recovery code is not valid, or has already been used", "two_factor_invalid"))
			return op, false
		}
		op.RecoveryHashes = rest
		return op, true
	}
	step, ok, err := d.checkSealedTOTP(op.TOTPSecretRef, op.TOTPLastStep, body.Code, time.Now())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not check the code"))
		return op, false
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errCode("that code is not right", "two_factor_invalid"))
		return op, false
	}
	op.TOTPLastStep = step
	return op, true
}

func (d Deps) recordOperator(what string, op platform.Operator) {
	if d.Recorder == nil {
		return
	}
	d.Recorder.Record(what, "auth", map[string]any{"operator_id": op.ID, "email": op.Email}, "operator account security")
}
