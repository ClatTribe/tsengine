package platformapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// scim.go: the company's identity provider keeps the seat list true.
//
// Single sign-on decides who may sign IN. It does nothing when someone LEAVES: their seat stays, and so
// does every session they hold, until somebody here remembers to remove them. For a product that holds a
// map of the company's exploitable exposure, that is the gap that matters, and SCIM 2.0 (RFC 7643/7644)
// is how Okta and Entra ID close it — the provider creates a seat when someone is assigned the app and
// deactivates it the moment they are unassigned or leave.
//
// What it is allowed to do, and what it refuses:
//   - It CREATES seats in the workspace's default role and REACTIVATES/DEACTIVATES them. It never changes a
//     role, and never creates an owner: ownership is a decision made in this product, not an assignment in
//     somebody's directory.
//   - Deactivation DISABLES, it never deletes. Approvals, attestations and risk decisions a person signed must
//     keep naming a real seat. A disabled seat signs in nowhere and every session it held is ended
//     (resolveSession refuses it too, so a session that survives the delete is still useless).
//   - The workspace OWNER cannot be deactivated by provisioning. A directory sync that removed the only
//     person able to change settings would lock the workspace out of itself; the refusal says why.
//   - A filter we do not understand is REFUSED, never answered with everyone. An identity provider asks
//     "does this person exist?" with a filter; answering an unparsed filter with the full list would tell it
//     every person matches, and it would then act on the wrong account.
//   - The token is the workspace's, minted by the owner, shown ONCE and stored as a digest. It embeds the
//     workspace id so it can be checked without an index over every tenant's tokens.

const (
	scimTokenPrefix = "tsscim_"
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimMaxPage     = 200
)

// scimRoles are the seats provisioning may create. Owner is deliberately absent.
var scimRoles = map[string]bool{platform.RoleMember: true, platform.RoleEmployee: true, platform.RoleAuditor: true}

func scimDigest(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func mintSCIMToken(tenantID string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return scimTokenPrefix + tenantID + "." + hex.EncodeToString(b), nil
}

// ── settings (owner-only by the /v1/settings/ prefix) ─────────────────────────────────────────────────

type scimSettingsView struct {
	Configured  bool      `json:"configured"`
	BaseURL     string    `json:"base_url"`
	TokenPrefix string    `json:"token_prefix,omitempty"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitzero"`
	LastUsedAt  time.Time `json:"last_used_at,omitzero"`
	DefaultRole string    `json:"default_role,omitempty"`
	Provisioned int       `json:"provisioned"`
	Deactivated int       `json:"deactivated"`
	// Token is present only in the response that minted it.
	Token string `json:"token,omitempty"`
}

func (d Deps) scimView(ctx context.Context, t platform.Tenant) scimSettingsView {
	v := scimSettingsView{BaseURL: strings.TrimRight(d.PublicURL, "/") + "/scim/v2"}
	if c := t.SCIM; c != nil {
		v.Configured, v.TokenPrefix, v.CreatedBy, v.CreatedAt = true, c.TokenPrefix, c.CreatedBy, c.CreatedAt
		v.LastUsedAt, v.DefaultRole = c.LastUsedAt, c.DefaultRole
	}
	if users, err := d.Store.ListUsers(ctx, t.ID); err == nil {
		for _, u := range users {
			if u.ProvisionedBy == "scim" {
				v.Provisioned++
			}
			if u.Disabled {
				v.Deactivated++
			}
		}
	}
	return v
}

func (d Deps) handleGetSCIMSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, d.scimView(r.Context(), t))
}

// handleMintSCIMToken creates (or rotates) the provisioning token. Rotating ends the old one immediately.
func (d Deps) handleMintSCIMToken(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		DefaultRole string `json:"default_role"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body)
	role := strings.ToLower(strings.TrimSpace(body.DefaultRole))
	if role == "" {
		role = platform.RoleMember
	}
	if !scimRoles[role] {
		writeJSON(w, http.StatusBadRequest, errCode("default_role must be member, employee or auditor — provisioning never creates an owner", "bad_role"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	tok, err := mintSCIMToken(tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	by := "platform"
	if u, ok := d.actingUser(r); ok {
		by = u.Email
	}
	rotated := t.SCIM != nil
	t.SCIM = &platform.SCIMConfig{TokenHash: scimDigest(tok), TokenPrefix: tok[:len(scimTokenPrefix)+6] + "…",
		CreatedBy: by, CreatedAt: time.Now().UTC(), DefaultRole: role}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	d.recordSCIM(tenantID, "scim token minted", map[string]any{"by": by, "rotated": rotated, "default_role": role})
	v := d.scimView(r.Context(), t)
	v.Token = tok
	writeJSON(w, http.StatusOK, v)
}

func (d Deps) handleRevokeSCIM(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	t.SCIM = nil
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	d.recordSCIM(tenantID, "scim token revoked", nil)
	writeJSON(w, http.StatusOK, d.scimView(r.Context(), t))
}

// ── the SCIM endpoint ─────────────────────────────────────────────────────────────────────────────────

func scimError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	b := map[string]any{"schemas": []string{scimErrorSchema}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		b["scimType"] = scimType
	}
	_ = json.NewEncoder(w).Encode(b)
}

func scimJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// scimAuth resolves the workspace from its provisioning token. Any failure is the same 401: which part
// was wrong is not something to tell a caller who does not hold the token.
func (d Deps) scimAuth(h func(w http.ResponseWriter, r *http.Request, t platform.Tenant)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		rest, ok := strings.CutPrefix(tok, scimTokenPrefix)
		i := strings.LastIndex(rest, ".")
		if !ok || i <= 0 {
			scimError(w, http.StatusUnauthorized, "", "invalid provisioning token")
			return
		}
		t, err := d.Store.GetTenant(r.Context(), rest[:i])
		if err != nil || t.SCIM == nil ||
			subtle.ConstantTimeCompare([]byte(scimDigest(tok)), []byte(t.SCIM.TokenHash)) != 1 {
			scimError(w, http.StatusUnauthorized, "", "invalid provisioning token")
			return
		}
		if time.Since(t.SCIM.LastUsedAt) > time.Minute {
			t.SCIM.LastUsedAt = time.Now().UTC()
			_ = d.Store.PutTenant(r.Context(), t)
		}
		h(w, r, t)
	}
}

func (d Deps) scimResource(u platform.User) map[string]any {
	res := map[string]any{
		"schemas":  []string{scimUserSchema},
		"id":       u.ID,
		"userName": u.Email,
		"active":   !u.Disabled,
		"emails":   []map[string]any{{"value": u.Email, "primary": true, "type": "work"}},
		"meta": map[string]any{
			"resourceType": "User",
			"created":      u.CreatedAt.UTC().Format(time.RFC3339),
			"location":     strings.TrimRight(d.PublicURL, "/") + "/scim/v2/Users/" + u.ID,
		},
	}
	if u.Name != "" {
		res["displayName"] = u.Name
		res["name"] = map[string]any{"formatted": u.Name}
	}
	if u.ExternalID != "" {
		res["externalId"] = u.ExternalID
	}
	return res
}

func handleSCIMServiceProviderConfig(w http.ResponseWriter, _ *http.Request, _ platform.Tenant) {
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": scimMaxPage},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token",
			"description": "The workspace provisioning token from Settings"}},
	})
}

// scimFilter is the only filter grammar accepted: `<attr> eq "<value>"` for userName or externalId, which
// is what Okta and Entra send to ask whether a person exists.
var scimFilter = regexp.MustCompile(`(?i)^\s*(userName|externalId)\s+eq\s+"([^"]*)"\s*$`)

func (d Deps) handleSCIMListUsers(w http.ResponseWriter, r *http.Request, t platform.Tenant) {
	users, err := d.Store.ListUsers(r.Context(), t.ID)
	if err != nil {
		scimError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	if f := strings.TrimSpace(r.URL.Query().Get("filter")); f != "" {
		m := scimFilter.FindStringSubmatch(f)
		if m == nil {
			scimError(w, http.StatusBadRequest, "invalidFilter",
				`only 'userName eq "…"' and 'externalId eq "…"' are supported; refusing rather than answering with every user`)
			return
		}
		var kept []platform.User
		for _, u := range users {
			if (strings.EqualFold(m[1], "userName") && strings.EqualFold(u.Email, m[2])) ||
				(strings.EqualFold(m[1], "externalId") && u.ExternalID != "" && u.ExternalID == m[2]) {
				kept = append(kept, u)
			}
		}
		users = kept
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil || count < 0 || count > scimMaxPage {
		count = scimMaxPage
	}
	total := len(users)
	from := min(start-1, total)
	to := min(from+count, total)
	page := make([]any, 0, to-from)
	for _, u := range users[from:to] {
		page = append(page, d.scimResource(u))
	}
	scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimListSchema}, "totalResults": total,
		"startIndex": start, "itemsPerPage": len(page), "Resources": page})
}

func (d Deps) scimUser(w http.ResponseWriter, r *http.Request, t platform.Tenant) (platform.User, bool) {
	u, err := d.Store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil || u.TenantID != t.ID {
		scimError(w, http.StatusNotFound, "", "no such user in this workspace")
		return u, false
	}
	return u, true
}

func (d Deps) handleSCIMGetUser(w http.ResponseWriter, r *http.Request, t platform.Tenant) {
	if u, ok := d.scimUser(w, r, t); ok {
		scimJSON(w, http.StatusOK, d.scimResource(u))
	}
}

// scimUserBody is the subset of the core User schema provisioning sends and we act on.
type scimUserBody struct {
	UserName    string `json:"userName"`
	ExternalID  string `json:"externalId"`
	DisplayName string `json:"displayName"`
	Active      *bool  `json:"active"`
	Name        struct {
		Formatted  string `json:"formatted"`
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

func (b scimUserBody) email() string {
	if e := strings.ToLower(strings.TrimSpace(b.UserName)); strings.Contains(e, "@") {
		return e
	}
	for _, e := range b.Emails {
		if e.Primary && strings.Contains(e.Value, "@") {
			return strings.ToLower(strings.TrimSpace(e.Value))
		}
	}
	for _, e := range b.Emails {
		if strings.Contains(e.Value, "@") {
			return strings.ToLower(strings.TrimSpace(e.Value))
		}
	}
	return ""
}

func (b scimUserBody) name() string {
	if n := strings.TrimSpace(b.DisplayName); n != "" {
		return n
	}
	if n := strings.TrimSpace(b.Name.Formatted); n != "" {
		return n
	}
	return strings.TrimSpace(strings.TrimSpace(b.Name.GivenName) + " " + strings.TrimSpace(b.Name.FamilyName))
}

func (d Deps) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request, t platform.Tenant) {
	var b scimUserBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&b); err != nil {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "the request body is not a SCIM user")
		return
	}
	email := b.email()
	if email == "" {
		scimError(w, http.StatusBadRequest, "invalidValue", "userName (or a primary email) must be an email address")
		return
	}
	switch existing, err := d.Store.GetUserByEmail(r.Context(), email); {
	case err == nil && existing.TenantID == t.ID:
		scimError(w, http.StatusConflict, "uniqueness", "a seat for "+email+" already exists in this workspace")
		return
	case err == nil:
		// Emails are globally unique; whose workspace holds it is not this caller's business.
		scimError(w, http.StatusConflict, "uniqueness", "userName is already in use")
		return
	case !errors.Is(err, store.ErrNotFound):
		scimError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	role := t.SCIM.DefaultRole
	if !scimRoles[role] {
		role = platform.RoleMember
	}
	u := platform.User{ID: d.newID("usr"), TenantID: t.ID, Email: email, Name: b.name(), Role: role,
		CreatedAt: time.Now().UTC(), ProvisionedBy: "scim", ExternalID: strings.TrimSpace(b.ExternalID)}
	if b.Active != nil && !*b.Active {
		u.Disabled, u.DisabledAt, u.DisabledBy = true, time.Now().UTC(), "scim"
	}
	if err := d.Store.PutUser(r.Context(), u); err != nil {
		scimError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	d.recordSCIM(t.ID, "seat provisioned", map[string]any{"email": email, "role": role, "active": !u.Disabled})
	scimJSON(w, http.StatusCreated, d.scimResource(u))
}

// setActive applies an active flag. Refuses to deactivate the workspace owner.
func (d Deps) setActive(ctx context.Context, u *platform.User, active bool) error {
	if active == !u.Disabled {
		return nil
	}
	if !active {
		if u.Role == platform.RoleOwner {
			return errOwnerDeprovision
		}
		u.Disabled, u.DisabledAt, u.DisabledBy = true, time.Now().UTC(), "scim"
		return nil
	}
	u.Disabled, u.DisabledAt, u.DisabledBy = false, time.Time{}, ""
	return nil
}

var errOwnerDeprovision = errors.New("the workspace owner cannot be deactivated by provisioning — a directory change must not " +
	"lock the workspace out of itself. Transfer ownership in the product first.")

// saveSCIMUser stores the change and, when the seat was just deactivated, ends every session it held.
func (d Deps) saveSCIMUser(ctx context.Context, before bool, u platform.User) error {
	if err := d.Store.PutUser(ctx, u); err != nil {
		return err
	}
	if u.Disabled && !before {
		if err := d.Store.DeleteSessionsForUser(ctx, u.ID); err != nil {
			// resolveSession refuses a disabled seat anyway; record that the delete failed rather than
			// pretend it ran.
			d.recordSCIM(u.TenantID, "seat deactivated; ending its sessions failed (they are refused regardless)",
				map[string]any{"email": u.Email, "error": err.Error()})
			return nil
		}
		d.recordSCIM(u.TenantID, "seat deactivated by provisioning", map[string]any{"email": u.Email})
	} else if !u.Disabled && before {
		d.recordSCIM(u.TenantID, "seat reactivated by provisioning", map[string]any{"email": u.Email})
	}
	return nil
}

func (d Deps) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request, t platform.Tenant) {
	u, ok := d.scimUser(w, r, t)
	if !ok {
		return
	}
	var b scimUserBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&b); err != nil {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "the request body is not a SCIM user")
		return
	}
	// The email is the sign-in identity; a provider renaming it is refused rather than silently moving a
	// seat (and everything it signed) onto a different address.
	if e := b.email(); e != "" && !strings.EqualFold(e, u.Email) {
		scimError(w, http.StatusBadRequest, "mutability", "userName cannot be changed by provisioning")
		return
	}
	before := u.Disabled
	if n := b.name(); n != "" {
		u.Name = n
	}
	if x := strings.TrimSpace(b.ExternalID); x != "" {
		u.ExternalID = x
	}
	if b.Active != nil {
		if err := d.setActive(r.Context(), &u, *b.Active); err != nil {
			scimError(w, http.StatusConflict, "mutability", err.Error())
			return
		}
	}
	if err := d.saveSCIMUser(r.Context(), before, u); err != nil {
		scimError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	scimJSON(w, http.StatusOK, d.scimResource(u))
}

// scimBool reads a bool that providers send either as JSON true/false or as "True"/"False" (Entra ID).
func scimBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func (d Deps) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request, t platform.Tenant) {
	u, ok := d.scimUser(w, r, t)
	if !ok {
		return
	}
	var body struct {
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || len(body.Operations) == 0 {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "a PatchOp with at least one operation is required")
		return
	}
	before := u.Disabled
	for _, op := range body.Operations {
		kind := strings.ToLower(op.Op)
		if kind != "replace" && kind != "add" {
			continue // remove of an optional attribute changes nothing we act on
		}
		attrs := map[string]any{}
		if p := strings.TrimSpace(op.Path); p != "" {
			attrs[p] = op.Value
		} else if m, ok := op.Value.(map[string]any); ok {
			attrs = m
		}
		for k, v := range attrs {
			switch strings.ToLower(k) {
			case "active":
				a, ok := scimBool(v)
				if !ok {
					scimError(w, http.StatusBadRequest, "invalidValue", "active must be true or false")
					return
				}
				if err := d.setActive(r.Context(), &u, a); err != nil {
					scimError(w, http.StatusConflict, "mutability", err.Error())
					return
				}
			case "displayname", "name.formatted":
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					u.Name = strings.TrimSpace(s)
				}
			case "externalid":
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					u.ExternalID = strings.TrimSpace(s)
				}
			case "username":
				if s, ok := v.(string); ok && !strings.EqualFold(strings.TrimSpace(s), u.Email) {
					scimError(w, http.StatusBadRequest, "mutability", "userName cannot be changed by provisioning")
					return
				}
			}
		}
	}
	if err := d.saveSCIMUser(r.Context(), before, u); err != nil {
		scimError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	scimJSON(w, http.StatusOK, d.scimResource(u))
}

// handleSCIMDeleteUser DEACTIVATES. The seat is kept so what it signed keeps naming a real person.
func (d Deps) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request, t platform.Tenant) {
	u, ok := d.scimUser(w, r, t)
	if !ok {
		return
	}
	before := u.Disabled
	if err := d.setActive(r.Context(), &u, false); err != nil {
		scimError(w, http.StatusConflict, "mutability", err.Error())
		return
	}
	if err := d.saveSCIMUser(r.Context(), before, u); err != nil {
		scimError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) recordSCIM(tenantID, what string, extra map[string]any) {
	if d.Recorder == nil {
		return
	}
	m := map[string]any{"tenant_id": tenantID}
	for k, v := range extra {
		m[k] = v
	}
	d.Recorder.Record(what, "scim", m, fmt.Sprintf("identity provider provisioning: %s", what))
}
