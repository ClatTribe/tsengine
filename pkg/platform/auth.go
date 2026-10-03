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
}

// StoreUser converts a User to its persisted form.
func StoreUser(u User) UserRecord {
	return UserRecord{User: u, Secrets: UserSecrets{
		ResetTokenHash: u.ResetTokenHash, ResetTokenExpires: u.ResetTokenExpires,
	}}
}

// Restore converts a persisted record back to a User, secrets included.
func (r UserRecord) Restore() User {
	u := r.User
	u.ResetTokenHash = r.Secrets.ResetTokenHash
	u.ResetTokenExpires = r.Secrets.ResetTokenExpires
	return u
}

// Session is an authenticated browser session: an opaque random Token that maps to a
// user + tenant until it expires. Stored server-side so it can be revoked on sign-out.
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	ExpiresAt time.Time `json:"expires_at"`
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
}

// OperatorSession authenticates an operator. Stored in a SEPARATE map from tenant Sessions so the two
// token namespaces never cross.
type OperatorSession struct {
	Token      string    `json:"token"`
	OperatorID string    `json:"operator_id"`
	ExpiresAt  time.Time `json:"expires_at"`
}
