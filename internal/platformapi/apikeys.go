package platformapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// apikeys.go mints, lists and revokes workspace API keys, and resolves one presented on a request.
// See platform.APIKey for why a machine credential is a different thing from a session, and
// apikey_scope.go for what a key may reach.

const (
	apiKeyDefaultDays = 90
	apiKeyMaxDays     = 365 // a year is the longest a CI secret should live unrotated
	apiKeyMaxActive   = 25  // past this, nobody can say which key a pipeline uses
	apiKeyTouchEvery  = time.Minute
)

// apiKeyDigest is the stored form of a key: the hex SHA-256 of the whole key. A key carries 160 bits
// of randomness, so an unsalted digest is safe to index on — there is no dictionary to precompute.
func apiKeyDigest(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// mintAPIKey returns a fresh key: the prefix, then 40 hex characters of randomness.
func mintAPIKey() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return platform.APIKeyPrefix + hex.EncodeToString(b), nil
}

// errKeyRefused carries the reason a presented key was refused, rendered to the caller. The reasons
// are specific on purpose: "expired" and "revoked" send a pipeline owner to different fixes, and
// neither tells an attacker anything a working key would not.
type errKeyRefused struct{ reason string }

func (e errKeyRefused) Error() string { return e.reason }

// resolveAPIKey reads a key from the Authorization header. ok=false means the header does not carry a
// key at all (so the caller tries the other credentials); err!=nil means it carried one we refuse.
func (d Deps) resolveAPIKey(r *http.Request) (platform.APIKey, bool, error) {
	tok := bearer(r)
	if !strings.HasPrefix(tok, platform.APIKeyPrefix) {
		return platform.APIKey{}, false, nil
	}
	k, err := d.Store.GetAPIKeyByHash(r.Context(), apiKeyDigest(tok))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// A session token is random base64url and can, very rarely, begin with the key prefix.
			// Hand those back to the session path rather than refusing a real sign-in.
			if _, serr := d.Store.GetSession(r.Context(), tok); serr == nil {
				return platform.APIKey{}, false, nil
			}
			return platform.APIKey{}, true, errKeyRefused{"invalid API key"}
		}
		return platform.APIKey{}, true, err
	}
	now := time.Now().UTC()
	switch {
	case k.Revoked():
		return k, true, errKeyRefused{"this API key has been revoked"}
	case !k.Usable(now):
		return k, true, errKeyRefused{"this API key has expired — create a new one in Settings → API keys"}
	}
	// Best effort: a failed touch must not fail the request the key was presented for.
	if now.Sub(k.LastUsedAt) >= apiKeyTouchEvery {
		k.LastUsedAt = now
		_ = d.Store.PutAPIKey(r.Context(), k)
	}
	return k, true, nil
}

type apiKeysResponse struct {
	Keys []platform.APIKey `json:"keys"`
	// Scopes names what each scope reaches, rendered verbatim next to the create form — a person
	// choosing a scope should read what it grants, not infer it from one word.
	Scopes map[string]string `json:"scopes"`
	Active int               `json:"active"`
}

var apiKeyScopeDescriptions = map[string]string{
	platform.APIKeyScopeRead:   "Read anything a workspace member can read. Cannot change anything.",
	platform.APIKeyScopeIngest: "Post scan results, inventories and events, run the pull-request check, and start a scan. Cannot approve, accept, suppress or change a setting.",
}

// GET /v1/settings/api-keys — every key the workspace has minted, revoked ones included (the record
// of which key did what keeps its referent). Digests are never returned.
func (d Deps) handleListAPIKeys(w http.ResponseWriter, r *http.Request, tenantID string) {
	ks, err := d.Store.ListAPIKeys(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	now := time.Now().UTC()
	out := make([]platform.APIKey, 0, len(ks))
	active := 0
	for _, k := range ks {
		if k.Usable(now) {
			active++
		}
		out = append(out, k.Redacted())
	}
	writeJSON(w, http.StatusOK, apiKeysResponse{Keys: out, Scopes: apiKeyScopeDescriptions, Active: active})
}

// POST /v1/settings/api-keys {name, scopes, expires_in_days} — owner-only by the settings prefix
// (owner_scope.go). The key is returned ONCE, in this response; only its digest is stored.
func (d Deps) handleCreateAPIKey(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Name          string   `json:"name"`
		Scopes        []string `json:"scopes"`
		ExpiresInDays int      `json:"expires_in_days"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 64 {
		writeJSON(w, http.StatusBadRequest, errBody("name the key after what will use it (1–64 characters) — e.g. \"github-actions\""))
		return
	}
	scopes, msg := normaliseScopes(body.Scopes)
	if msg != "" {
		writeJSON(w, http.StatusBadRequest, errBody(msg))
		return
	}
	days := body.ExpiresInDays
	switch {
	case days == 0:
		days = apiKeyDefaultDays
	case days < 0 || days > apiKeyMaxDays:
		writeJSON(w, http.StatusBadRequest, errBody("a key expires within a year — a key that never expires is one nobody rotates"))
		return
	}

	existing, err := d.Store.ListAPIKeys(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	now := time.Now().UTC()
	active := 0
	for _, k := range existing {
		if k.Usable(now) {
			active++
		}
	}
	if active >= apiKeyMaxActive {
		writeJSON(w, http.StatusConflict, errBody("this workspace already has the maximum number of active keys — revoke one no pipeline uses first"))
		return
	}

	key, err := mintAPIKey()
	if err != nil {
		respond(w, nil, err)
		return
	}
	k := platform.APIKey{
		ID:        d.newID("key"),
		TenantID:  tenantID,
		Name:      name,
		Prefix:    key[:len(platform.APIKeyPrefix)+8],
		Hash:      apiKeyDigest(key),
		Scopes:    scopes,
		CreatedBy: d.actorName(r),
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour),
	}
	if err := d.Store.PutAPIKey(r.Context(), k); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("api key created", "api_key_create",
			map[string]any{"tenant_id": tenantID, "key_id": k.ID, "prefix": k.Prefix, "scopes": k.Scopes,
				"expires_at": k.ExpiresAt, "by": k.CreatedBy}, "machine credential minted")
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"key":   k.Redacted(),
		"token": key,
		"note":  "Copy this key now — it is shown once and only a digest of it is stored.",
	})
}

// POST /v1/settings/api-keys/{id}/revoke — owner-only by the settings prefix. Revocation is recorded,
// not a delete, so the log of what a key did still names it.
func (d Deps) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	ks, err := d.Store.ListAPIKeys(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	for _, k := range ks {
		if k.ID != id {
			continue
		}
		if k.Revoked() {
			writeJSON(w, http.StatusOK, k.Redacted())
			return
		}
		k.RevokedAt = time.Now().UTC()
		k.RevokedBy = d.actorName(r)
		if err := d.Store.PutAPIKey(r.Context(), k); err != nil {
			respond(w, nil, err)
			return
		}
		if d.Recorder != nil {
			d.Recorder.Record("api key revoked", "api_key_revoke",
				map[string]any{"tenant_id": tenantID, "key_id": k.ID, "prefix": k.Prefix, "by": k.RevokedBy},
				"machine credential revoked")
		}
		writeJSON(w, http.StatusOK, k.Redacted())
		return
	}
	// Scoped to the tenant: another workspace's key id is simply not found here.
	writeJSON(w, http.StatusNotFound, errBody("api key not found"))
}

// normaliseScopes dedups and validates. An empty set is refused rather than defaulted: a key that can
// do nothing is a mistake, and a default would be a choice made on the person's behalf.
func normaliseScopes(in []string) ([]string, string) {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if !platform.ValidAPIKeyScope(s) {
			return nil, "unknown scope " + `"` + s + `"` + " — a key may be read, ingest, or both"
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, "choose at least one scope: read, ingest"
	}
	return out, ""
}

// actorName names the human making a request: the signed-in user's email, or the operator for the
// platform bearer. Taken from the credential, never from the body, so a key's creator cannot be typed.
func (d Deps) actorName(r *http.Request) string {
	if d.bearerOK(r) {
		return "platform operator"
	}
	if s, ok := d.resolveSession(r); ok {
		if u, err := d.Store.GetUser(r.Context(), s.UserID); err == nil {
			return u.Email
		}
	}
	return "unknown"
}
