package platformapi

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// White-label branding — GET/PUT /v1/settings/branding.
//
// The MSP / consultancy motion resells the managed tier under the partner's own name, and every
// outward artifact — the VAPT report, the public Trust Center — said TensorShield. Branding puts the
// partner's name, logo and support address on those artifacts. It rebrands prose and chrome only:
// the engine identifier in a report's provenance block stays, because that is evidence about how
// the assessment was produced, and a rebrand that erased it would be a claim about provenance.
//
// No secret here (a name, a public logo URL, an address), so it is stored plain like the contacts.

func (d Deps) handleGetBranding(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, brandingView(t))
}

func brandingView(t platform.Tenant) map[string]any {
	b := platform.Branding{}
	if t.Branding != nil {
		b = *t.Branding
	}
	return map[string]any{
		"branding":       b,
		"effective_name": t.Brand(),
		"white_labelled": t.WhiteLabelled(),
		"default_brand":  platform.DefaultBrand,
	}
}

// validateBranding bounds the fields. An empty name CLEARS the white-label (back to the product's
// brand); a logo must be an https URL so the public page never mixes content or loads from a
// scheme a browser will block silently; a support address must parse or be omitted.
func validateBranding(b platform.Branding) (*platform.Branding, string) {
	b.Name = strings.TrimSpace(b.Name)
	b.LogoURL = strings.TrimSpace(b.LogoURL)
	b.SupportEmail = strings.TrimSpace(b.SupportEmail)
	if b.Name == "" && b.LogoURL == "" && b.SupportEmail == "" {
		return nil, ""
	}
	if b.Name == "" {
		return nil, "a brand name is required — a logo or support address without a name would render an unnamed brand"
	}
	if len(b.Name) > 64 {
		return nil, "brand name must be 64 characters or fewer"
	}
	if b.LogoURL != "" {
		u, err := url.Parse(b.LogoURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || len(b.LogoURL) > 512 {
			return nil, "logo_url must be an https:// URL (512 characters or fewer)"
		}
	}
	if b.SupportEmail != "" {
		if _, err := mail.ParseAddress(b.SupportEmail); err != nil || len(b.SupportEmail) > 254 {
			return nil, "support_email must be a valid email address"
		}
	}
	return &b, ""
}

func (d Deps) handlePutBranding(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body platform.Branding
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	b, problem := validateBranding(body)
	if problem != "" {
		writeJSON(w, http.StatusBadRequest, errBody(problem))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	t.Branding = b
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, brandingView(t))
}

// tenantBrand is the name outward artifacts should carry for a tenant; the product's when the
// tenant cannot be read (an unreadable tenant must not become an unnamed document).
func (d Deps) tenantBrand(r *http.Request, tenantID string) string {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		return platform.DefaultBrand
	}
	return t.Brand()
}
