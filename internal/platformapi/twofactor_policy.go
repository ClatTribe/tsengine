package platformapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// twofactor_policy.go is the OWNER's policy that every person in the workspace signs in with a second
// factor — the tenant twin of TSENGINE_OPERATOR_REQUIRE_2FA, and the control a buyer's questionnaire
// actually asks about ("is MFA ENFORCED", not "is it available").
//
// The rules:
//   - Enforced at the shared auth gate, so no handler can forget it. A seat without two-factor is
//     refused everything with 403 two_factor_setup_required EXCEPT what enrolment needs — who am I,
//     sign out, change password, the 2FA endpoints — which sit behind sessionAuth, not that gate.
//   - Only the owner may turn it on or off (the settings prefix is owner-only), and the owner must
//     have it on THEMSELVES first: a policy switched on by someone who never proved the flow works
//     is the one most likely to strand everybody, its author included.
//   - Switching it on reports who it will gate, by name. A policy that silently locks a third of the
//     company out of the product mid-afternoon is a support incident, not a security control.
//   - While it holds, nobody may turn their own two-factor off (they would be locked out the moment
//     they did) — moving to a new phone is "replace", not "remove".
//   - Fail closed on doubt: a tenant that cannot be read is treated as requiring it for a seat that
//     has no second factor. Refusing one request on a store blip is cheap; letting a password-only
//     session through a policy the owner set is the failure this exists to prevent.
//   - Machine credentials are out of scope by design: an API key is not a person and has no phone.

// twoFactorBlocks reports whether the workspace's policy refuses this person right now.
func (d Deps) twoFactorBlocks(r *http.Request, tenantID string, u platform.User) bool {
	if u.TwoFactorEnabled {
		return false
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		return true
	}
	return t.RequireTwoFactor
}

type securityPolicyView struct {
	RequireTwoFactor bool       `json:"require_two_factor"`
	RequiredBy       string     `json:"required_by,omitempty"`
	RequiredAt       *time.Time `json:"required_at,omitempty"`
	// WithoutTwoFactor names the people who have not enrolled — who the policy gates now, or WOULD
	// gate if switched on. Names, not a count: the owner's next step is to message them.
	WithoutTwoFactor []string `json:"without_two_factor"`
	Seats            int      `json:"seats"`
}

func (d Deps) securityPolicy(r *http.Request, tenantID string) (securityPolicyView, error) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		return securityPolicyView{}, err
	}
	users, err := d.Store.ListUsers(r.Context(), tenantID)
	if err != nil {
		return securityPolicyView{}, err
	}
	v := securityPolicyView{RequireTwoFactor: t.RequireTwoFactor, RequiredBy: t.RequireTwoFactorBy,
		Seats: len(users), WithoutTwoFactor: []string{}}
	if !t.RequireTwoFactorAt.IsZero() {
		at := t.RequireTwoFactorAt
		v.RequiredAt = &at
	}
	for _, u := range users {
		if !u.TwoFactorEnabled {
			v.WithoutTwoFactor = append(v.WithoutTwoFactor, u.Email)
		}
	}
	sort.Strings(v.WithoutTwoFactor)
	return v, nil
}

// handleGetSecurityPolicy reports the policy and who has not enrolled.
func (d Deps) handleGetSecurityPolicy(w http.ResponseWriter, r *http.Request, tenantID string) {
	v, err := d.securityPolicy(r, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handlePutSecurityPolicy turns the policy on or off (owner-only by the settings prefix).
func (d Deps) handlePutSecurityPolicy(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		RequireTwoFactor bool `json:"require_two_factor"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	actor := "platform operator"
	if s, ok := d.resolveSession(r); ok {
		u, uerr := d.Store.GetUser(r.Context(), s.UserID)
		if uerr != nil {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		if body.RequireTwoFactor && !u.TwoFactorEnabled {
			writeJSON(w, http.StatusConflict, errCode(
				"turn on two-factor sign-in for your own account first — a policy switched on by someone who has not "+
					"been through the flow is the one most likely to lock everybody out", "owner_two_factor_off"))
			return
		}
		actor = strings.TrimSpace(u.Email)
	}
	t.RequireTwoFactor = body.RequireTwoFactor
	if body.RequireTwoFactor {
		t.RequireTwoFactorBy, t.RequireTwoFactorAt = actor, time.Now().UTC()
	} else {
		t.RequireTwoFactorBy, t.RequireTwoFactorAt = "", time.Time{}
	}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	what := "two-factor sign-in no longer required"
	if body.RequireTwoFactor {
		what = "two-factor sign-in required for every seat"
	}
	if d.Recorder != nil {
		d.Recorder.Record(what, "auth", map[string]any{"tenant_id": tenantID, "by": actor}, "workspace security policy")
	}
	v, err := d.securityPolicy(r, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, v)
}
