package platform

import "time"

// APIKey is a MACHINE credential for one workspace: what a CI job, a collector or a scheduled export
// authenticates with. Before it existed the documented way to wire the PR check into CI was to paste a
// person's SESSION token — which expires under the job, carries every right that person has (approve a
// fix, change a setting, halt automation), and names a human as the actor for traffic no human sent.
//
// Three properties make it a different kind of thing from a session, and each is load-bearing:
//
//   - SCOPED, closed by default. A key carries scopes (read, ingest), and the auth gate admits only what
//     a scope names. There is deliberately NO scope that decides anything — approving a fix, accepting a
//     risk, publishing a policy, changing a setting. Those require a NAMED HUMAN (§18.4), and a key is
//     not one; a leaked CI key must be able to post a scan and nothing that changes what the workspace
//     trusts or does.
//   - STORED AS A DIGEST. Only the SHA-256 of the key is kept; the key itself is shown once at creation.
//     A key is a bearer credential with a long life, and a store dump must not be a list of them.
//   - IT EXPIRES. There is no "never": a key that never expires is a key nobody rotates, and the one
//     found in an old build log still works. Revocation is recorded, never a delete, so the log of
//     which key did what keeps its referent.
type APIKey struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	// Prefix is the first characters of the key (e.g. "tsk_1a2b3c4d") — enough to recognise which key
	// a log line or a CI secret refers to, far too short to use.
	Prefix string `json:"prefix"`
	// Hash is the hex SHA-256 of the full key. Never returned by the API (see Redacted).
	Hash      string    `json:"hash,omitempty"`
	Scopes    []string  `json:"scopes"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// LastUsedAt is refreshed at most once a minute — enough to answer "is this key still in use?"
	// before revoking it, without a store write on every request.
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
	RevokedAt  time.Time `json:"revoked_at,omitzero"`
	RevokedBy  string    `json:"revoked_by,omitempty"`
}

// API key scopes. Adding one is a decision about what a machine may do without a person: it needs an
// entry in the gate (internal/platformapi/apikey_scope.go) and nothing else grants it.
const (
	// APIKeyScopeRead may read (GET) what the workspace's members can read — dashboards, exports.
	APIKeyScopeRead = "read"
	// APIKeyScopeIngest may post scan results, inventories and events into the workspace, run the CI
	// PR check, and start a scan — the calls a pipeline or a collector makes. Nothing it can reach
	// decides, approves, suppresses or reconfigures.
	APIKeyScopeIngest = "ingest"
)

// APIKeyPrefix begins every key, so the gate can tell a key from a session token without a lookup and
// a secret scanner can recognise one in a leaked file.
const APIKeyPrefix = "tsk_"

// ValidAPIKeyScope reports whether s is a scope the gate knows.
func ValidAPIKeyScope(s string) bool { return s == APIKeyScopeRead || s == APIKeyScopeIngest }

// HasScope reports whether the key carries scope s.
func (k APIKey) HasScope(s string) bool {
	for _, x := range k.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

// Revoked reports whether the key has been revoked.
func (k APIKey) Revoked() bool { return !k.RevokedAt.IsZero() }

// Usable reports whether the key may authenticate a request at now: not revoked, not expired. A key
// with no expiry recorded is NOT usable — the creator never mints one, so a zero value means a record
// we did not write, and a credential of unknown provenance is refused rather than trusted.
func (k APIKey) Usable(now time.Time) bool {
	return !k.Revoked() && !k.ExpiresAt.IsZero() && now.Before(k.ExpiresAt)
}

// Redacted returns the key without its digest — the form every API response carries.
func (k APIKey) Redacted() APIKey {
	k.Hash = ""
	return k
}
