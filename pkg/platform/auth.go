package platform

import "time"

// User roles within a tenant.
const (
	RoleOwner  = "owner"  // created the workspace; full control
	RoleMember = "member" // invited teammate
	// RoleAuditor is READ-ONLY membership: the external SOC 2 / ISO auditor, a CPA-firm partner, a
	// prospective customer's security reviewer. They need the evidence — findings, control posture,
	// the compliance report, the evidence pack — and they must not be able to trigger a scan,
	// approve a fix, change a setting or invite anyone. Before this role the only way to give an
	// auditor access was a full member seat, and a full member can do all of those. Enforced in the
	// auth middleware (every non-read request is refused with read_only_role), not by hiding
	// buttons, so a hand-crafted request is refused the same way a click would be.
	RoleAuditor = "auditor"
	// RoleEmployee is the narrowest seat: a colleague who was asked to do their security training
	// and acknowledge the policies, and who has no business seeing the security estate.
	//
	// It exists because the training programme is unusable without it. Asking forty people to
	// complete their modules meant inviting forty MEMBERS, and a member can read every finding,
	// every attack path and every pentest report, start a scan and approve a fix. Nobody will send
	// that invite, so the programme that every framework requires would sit permanently unstarted.
	//
	// Enforced by an ALLOWLIST in the auth middleware, not a denylist and not by hiding buttons.
	// The direction matters: with a denylist every endpoint added later is exposed to the whole
	// company by default, and the person adding it has no reason to think about employees at all.
	// A test drives every registered route to hold the allowlist to that.
	RoleEmployee = "employee"
)

// User is a person who signs in to a tenant. Authentication is email + password
// (PasswordHash is a PBKDF2-encoded digest, NEVER returned by the API). A user belongs
// to exactly one tenant; email is globally unique so login can resolve the tenant.
type User struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Email        string    `json:"email"`
	Name         string    `json:"name,omitempty"`
	Role         string    `json:"role"` // RoleOwner | RoleMember | RoleAuditor | RoleEmployee
	PasswordHash string    `json:"password_hash,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// MustChangePassword is set when an account is provisioned with a temporary password
	// (an owner invite) and cleared the first time the user sets their own. While true the
	// app endpoints are blocked (403 password_change_required) so the temp password — which
	// the owner who issued it knows — cannot remain the standing credential.
	MustChangePassword bool `json:"must_change_password,omitempty"`
	// TwoFactorEnabled is true once the user has CONFIRMED an authenticator (a code from it verified),
	// never on setup alone — a secret generated and never scanned would lock the account out.
	TwoFactorEnabled bool `json:"two_factor_enabled,omitempty"`
	// TOTPSecretRef / TOTPPendingRef hold the authenticator seed SEALED by the vault (never plaintext,
	// §18.2 inv. 6): the confirmed one and one awaiting its first code. TOTPLastStep is the last time
	// step accepted, so an observed code cannot be replayed inside its window. RecoveryHashes are the
	// SHA-256 of the unused recovery codes. All json:"-" so no client ever sees them, and all persisted
	// through UserSecrets — the json:"-" tag alone would have the stores drop them (see UserRecord).
	TOTPSecretRef  string   `json:"-"`
	TOTPPendingRef string   `json:"-"`
	TOTPLastStep   int64    `json:"-"`
	RecoveryHashes []string `json:"-"`
	// ResetTokenHash is the SHA-256 (hex) of a one-time password-reset token; the raw token is
	// emailed to the user and never stored. ResetTokenExpires bounds validity. Both clear on
	// completion. Never serialized to clients (json:"-").
	ResetTokenHash    string    `json:"-"`
	ResetTokenExpires time.Time `json:"-"`
}

// UserRecord is how a User is PERSISTED. User's secret fields are json:"-" so no handler that
// writes a User to a client can leak them — and that same tag made every JSON-backed store (SQLite,
// file, Postgres) DROP them on save. Measured: a password-reset token set by /v1/auth/forgot came back
// empty from GetUser on SQLite, so every reset link on a production deployment was rejected as
// invalid, while the in-memory store the tests use kept the struct and the suite stayed green.
//
// The fix keeps the API side closed by construction and gives the store its own shape: the secrets
// ride in a separate field that only exists on the storage type. Stores encode StoreUser(u) and decode
// back with Restore(); nothing else should use this type.
type UserRecord struct {
	User
	Secrets UserSecrets `json:"_secrets,omitzero"`
}

// UserSecrets are the User fields that must persist but must never be serialized to a client.
type UserSecrets struct {
	ResetTokenHash    string    `json:"reset_token_hash,omitempty"`
	ResetTokenExpires time.Time `json:"reset_token_expires,omitzero"`
	TOTPSecretRef     string    `json:"totp_secret_ref,omitempty"`
	TOTPPendingRef    string    `json:"totp_pending_ref,omitempty"`
	TOTPLastStep      int64     `json:"totp_last_step,omitempty"`
	RecoveryHashes    []string  `json:"recovery_hashes,omitempty"`
}

// StoreUser converts a User to its persisted form.
func StoreUser(u User) UserRecord {
	return UserRecord{User: u, Secrets: UserSecrets{
		ResetTokenHash: u.ResetTokenHash, ResetTokenExpires: u.ResetTokenExpires,
		TOTPSecretRef: u.TOTPSecretRef, TOTPPendingRef: u.TOTPPendingRef,
		TOTPLastStep: u.TOTPLastStep, RecoveryHashes: u.RecoveryHashes,
	}}
}

// Restore converts a persisted record back to a User, secrets included.
func (r UserRecord) Restore() User {
	u := r.User
	u.ResetTokenHash = r.Secrets.ResetTokenHash
	u.ResetTokenExpires = r.Secrets.ResetTokenExpires
	u.TOTPSecretRef = r.Secrets.TOTPSecretRef
	u.TOTPPendingRef = r.Secrets.TOTPPendingRef
	u.TOTPLastStep = r.Secrets.TOTPLastStep
	u.RecoveryHashes = r.Secrets.RecoveryHashes
	return u
}

// Session is an authenticated browser session: an opaque random Token that maps to a
// user + tenant until it expires. Stored server-side so it can be revoked on sign-out.
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	ExpiresAt time.Time `json:"expires_at"`
	// MFAPending marks a HALF-session: the password was right and the second factor is still owed. It
	// authenticates NOTHING — resolveSession refuses it — and is only redeemable at the 2FA verify
	// endpoint, which deletes it and issues a real session. MFAAttempts counts wrong codes against it.
	MFAPending  bool `json:"mfa_pending,omitempty"`
	MFAAttempts int  `json:"mfa_attempts,omitempty"`
	// Via records how the session was established ("password" or "sso"); an SSO session is shorter so
	// that disabling someone at the identity provider takes effect within hours, not weeks.
	Via string `json:"via,omitempty"`
	// IdPMFA is true when the identity provider asserted a second factor for this sign-in (the ID
	// token's amr). It satisfies the workspace's two-factor policy for this session only.
	IdPMFA bool `json:"idp_mfa,omitempty"`
	// SSOFlow marks an SSO sign-in IN PROGRESS: the PKCE verifier and nonce, held server-side between
	// the redirect to the provider and its return. It authenticates nothing (resolveSession refuses
	// it) and is single use.
	SSOFlow *SSOFlow `json:"sso_flow,omitempty"`
}

// SSOFlow is the server-side state of one SSO sign-in between redirect and callback.
type SSOFlow struct {
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	Email    string `json:"email"`
}

// Operator is a CROSS-TENANT practitioner identity — the MSP's expert or our managed delivery expert
// who works the human-in-the-loop across a book of client tenants. It is a DELIBERATELY SEPARATE
// namespace from the tenant-scoped User/Session (different store maps, different sessions, different
// auth middleware) so an operator credential can never be confused with a tenant session and tenant
// isolation (§18.2 inv. 2) is untouched. An operator's Email is matched against tenant practitioner
// rosters to scope what they can see; operator ACCOUNTS are provisioned by the deployment operator
// (platform token), not self-serve.
type Operator struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name,omitempty"`
	Firm         string    `json:"firm,omitempty"`
	PasswordHash string    `json:"password_hash,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// Two-factor sign-in, the same shape and the same rules as User's (internal/platformapi/
	// twofactor.go). An operator credential reaches every client on the practitioner's roster, so it is
	// the more valuable one to protect. Secrets are json:"-" and persisted through OperatorRecord.
	TwoFactorEnabled bool     `json:"two_factor_enabled,omitempty"`
	TOTPSecretRef    string   `json:"-"`
	TOTPPendingRef   string   `json:"-"`
	TOTPLastStep     int64    `json:"-"`
	RecoveryHashes   []string `json:"-"`
}

// OperatorRecord is how an Operator is PERSISTED — the UserRecord pattern, for the same reason: the
// json:"-" secrets would otherwise be dropped by every JSON-backed store.
type OperatorRecord struct {
	Operator
	Secrets UserSecrets `json:"_secrets,omitzero"`
}

// StoreOperator converts an Operator to its persisted form.
func StoreOperator(o Operator) OperatorRecord {
	return OperatorRecord{Operator: o, Secrets: UserSecrets{
		TOTPSecretRef: o.TOTPSecretRef, TOTPPendingRef: o.TOTPPendingRef,
		TOTPLastStep: o.TOTPLastStep, RecoveryHashes: o.RecoveryHashes,
	}}
}

// Restore converts a persisted record back to an Operator, secrets included.
func (r OperatorRecord) Restore() Operator {
	o := r.Operator
	o.TOTPSecretRef = r.Secrets.TOTPSecretRef
	o.TOTPPendingRef = r.Secrets.TOTPPendingRef
	o.TOTPLastStep = r.Secrets.TOTPLastStep
	o.RecoveryHashes = r.Secrets.RecoveryHashes
	return o
}

// OperatorSession authenticates an operator. Stored in a SEPARATE map from tenant Sessions so the two
// token namespaces never cross.
type OperatorSession struct {
	Token      string    `json:"token"`
	OperatorID string    `json:"operator_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	// MFAPending / MFAAttempts: the half-session rule, as on Session.
	MFAPending  bool `json:"mfa_pending,omitempty"`
	MFAAttempts int  `json:"mfa_attempts,omitempty"`
}
