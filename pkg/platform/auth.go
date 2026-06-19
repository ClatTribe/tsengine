package platform

import "time"

// User roles within a tenant.
const (
	RoleOwner  = "owner"  // created the workspace; full control
	RoleMember = "member" // invited teammate
)

// User is a person who signs in to a tenant. Authentication is email + password
// (PasswordHash is a PBKDF2-encoded digest, NEVER returned by the API). A user belongs
// to exactly one tenant; email is globally unique so login can resolve the tenant.
type User struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Email        string    `json:"email"`
	Name         string    `json:"name,omitempty"`
	Role         string    `json:"role"` // RoleOwner | RoleMember
	PasswordHash string    `json:"password_hash,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// MustChangePassword is set when an account is provisioned with a temporary password
	// (an owner invite) and cleared the first time the user sets their own. While true the
	// app endpoints are blocked (403 password_change_required) so the temp password — which
	// the owner who issued it knows — cannot remain the standing credential.
	MustChangePassword bool `json:"must_change_password,omitempty"`
}

// Session is an authenticated browser session: an opaque random Token that maps to a
// user + tenant until it expires. Stored server-side so it can be revoked on sign-out.
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	ExpiresAt time.Time `json:"expires_at"`
}
