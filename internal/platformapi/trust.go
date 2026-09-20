package platformapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/trustcenter"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The public Trust Center (a shareable "we're secure" page, like Vanta/Drata trust pages).
// This file serves the AGGREGATE posture — the org name and per-framework coverage %. The
// document tier behind it lives in trustcenter.go.
//
// It NEVER exposes findings, endpoints, or which specific controls are gaps: a gap list is
// an attacker's roadmap. That rule is why the document tier has a structural minimum gate
// (platform.DocKind.MinVisibility) rather than a setting — a VAPT report is that same gap list
// with reproduction steps attached, and an owner should not be one click from publishing it.
//
// Access is gated by an HMAC share token so a tenant id alone can't enumerate it. The token is
// derived, not stored, but it is now VERSIONED (see trustTokenFor) so a leaked link can be
// revoked without rotating the platform secret out from under every other tenant.

// trustFrameworks is the set surfaced on the public Trust Center — the full framework set
// (grc.Frameworks), so the public coverage page reflects everything the tenant has posture
// for, not a stale six. Frameworks with no control state are skipped at render time.
var trustFrameworks = grc.Frameworks

// trustTokenFor derives a tenant's non-guessable Trust Center share token at the config's
// current revocation version.
//
// The version is what makes a leaked link killable. Without it the token was a bare HMAC over
// the tenant id — PERMANENT, since the only way to change it was rotating the platform secret,
// which would take every other tenant's link (and the OAuth state keyed by the same secret)
// with it. Meanwhile the public page told readers a link "has been revoked", describing a
// capability that did not exist.
//
// Versions 0 and 1 deliberately mint the SAME token, so every link issued before this existed
// keeps working; the first revocation moves to 2.
func (d Deps) trustTokenFor(tenant string, cfg platform.TrustCenterConfig) string {
	mac := hmac.New(sha256.New, []byte(d.Token))
	seed := "trust-center:" + tenant
	if cfg.TokenVersion > 1 {
		seed = fmt.Sprintf("trust-center:%s:v%d", tenant, cfg.TokenVersion)
	}
	mac.Write([]byte(seed))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:24]
}

type trustFramework struct {
	Framework string `json:"framework"`
	// Coverage is ASSESSMENT coverage (assessed / assessable %), NOT a met/total "compliance score" — so the
	// customer-facing Trust Center never reads as a false "100% compliant" (the no-false-compliant rule, the
	// same honesty layer the in-app /compliance uses). 0 when the assessable universe is unknown.
	Coverage   int `json:"coverage"`
	Assessed   int `json:"assessed"`   // controls a finding has actually touched (met + gap)
	Assessable int `json:"assessable"` // controls the crosswalk CAN evaluate
	Gaps       int `json:"gaps"`
}

type trustView struct {
	Org string `json:"org"`
	// Brand / BrandLogoURL / BrandSupportEmail are the white-label chrome (platform.Tenant.Branding).
	// WhiteLabelled tells the page whether to show the product's own "see how it works" link: on a
	// partner-branded page that link would name a company the buyer has never heard of.
	Brand             string           `json:"brand"`
	BrandLogoURL      string           `json:"brand_logo_url,omitempty"`
	BrandSupportEmail string           `json:"brand_support_email,omitempty"`
	WhiteLabelled     bool             `json:"white_labelled"`
	Headline          string           `json:"headline,omitempty"`
	Monitored         bool             `json:"monitored"`
	Signed            bool             `json:"signed"`
	Frameworks        []trustFramework `json:"frameworks"`
	// Documents is what THIS visitor sees: public rows readable, gated rows listed but locked,
	// anything the tenant cannot actually produce absent entirely. Non-nil empty so it
	// serialises as [] — a null would crash the public page's .map, on the one URL a customer
	// hands to their own customers.
	Documents []trustcenter.Entry `json:"documents"`
	// Granted says whether the presented access token currently unlocks the gated tier, and
	// NDAPending distinguishes the two ways it might not: approval outstanding, or approved
	// with the agreement still to accept. Collapsed into one flag the page could not tell the
	// buyer whether to wait for a human or to click accept.
	Granted      bool   `json:"granted"`
	NDARequired  bool   `json:"nda_required"`
	NDAPending   bool   `json:"nda_pending"`
	NDAText      string `json:"nda_text,omitempty"`
	ContactEmail string `json:"contact_email,omitempty"`
	GeneratedAt  string `json:"generated_at"`
}

// handleTrustLink (authed, tenant-scoped) returns the caller's own Trust Center token so the
// UI can render a shareable link.
func (d Deps) handleTrustLink(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	cfg := trustConfigOf(t)
	tok := d.trustTokenFor(tenantID, cfg)
	writeJSON(w, http.StatusOK, map[string]string{
		"tenant": tenantID,
		"token":  tok,
		"path":   "/trust/" + tenantID + "?token=" + tok,
	})
}

// handleTrust (PUBLIC — no bearer) renders a tenant's Trust Center aggregate, gated by the
// HMAC share token. Safe-by-construction: org name + coverage % only.
func (d Deps) handleTrust(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	t, cfg, ok := d.trustTenantFor(r.Context(), tenant, r.URL.Query().Get("token"))
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return
	}
	req, granted := d.trustGrant(r.Context(), t.ID, cfg, r.URL.Query().Get("access"))
	avail, _ := d.trustAvailability(r.Context(), t.ID, cfg)
	ndaRequired := trustcenter.RequiresNDA(cfg)

	// MONITORED AND SIGNED ARE FACTS, NOT DECORATION.
	//
	// These were hardcoded `true`, three lines above a comment about never rendering a false "100%
	// compliant" on this very page. So a workspace that had never run a single scan published
	// "Continuously monitored · Re-scanned on every change" to its own customers — the most
	// expensive place in the product to overstate anything, because the reader is doing vendor due
	// diligence on someone who trusted us to describe them accurately.
	//
	// Monitored means a scan has actually completed. Signed means there is a signed decision trail
	// for this tenant — every Action is recorded into the ledger, so an action existing is the
	// evidence. Both understate on a read error: a page that cannot prove a claim must not make it.
	view := trustView{
		Org:           t.Name,
		Brand:         t.Brand(),
		WhiteLabelled: t.WhiteLabelled(),
		Headline:      cfg.Headline,
		Monitored:     d.tenantHasCompletedScan(r.Context(), tenant),
		Signed:        d.tenantHasSignedDecisions(r.Context(), tenant),
		// Non-nil empty slice so it serializes as [] not null on a tenant with no posture yet — a
		// null would crash the PUBLIC page's .map (the Go nil-slice → JSON-null footgun, on a URL
		// the customer shares with their own customers).
		Frameworks:  []trustFramework{},
		Documents:   trustcenter.Catalog(cfg, avail, granted),
		Granted:     granted,
		NDARequired: ndaRequired,
		// Approved, but the agreement is still outstanding — the state where the buyer's next
		// move is a click rather than a wait. Reported only to someone actually holding an
		// approved request, so it says nothing to a visitor with no token.
		NDAPending:   ndaRequired && req.Status == platform.TrustReqApproved && !req.Revoked && req.NDAAcceptedAt.IsZero(),
		ContactEmail: cfg.ContactEmail,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if t.Branding != nil {
		view.BrandLogoURL, view.BrandSupportEmail = t.Branding.LogoURL, t.Branding.SupportEmail
	}
	// The agreement text is served only to the buyer who has to accept it. A visitor with no
	// approved request has nothing to agree to, and publishing the terms to anyone who opens the
	// page invites them to be read as conditions on the public tier, which they are not.
	if view.NDAPending {
		view.NDAText = cfg.NDAText
	}
	if d.GRC != nil {
		for _, fw := range trustFrameworks {
			// Use the honest assessment-coverage layer (assessed / assessable), NOT met/total — so a thin
			// posture (a few controls touched, all met) can never render as a green "100% compliant" on a
			// page the tenant shares with its own customers (the no-false-compliant rule).
			cov, err := d.GRC.Coverage(r.Context(), tenant, fw)
			if err != nil || cov.AssessedControls == 0 {
				continue // no posture for this framework yet → don't list it
			}
			view.Frameworks = append(view.Frameworks, trustFramework{
				Framework: fw, Coverage: int(cov.AutomatedCoveragePct),
				Assessed: cov.AssessedControls, Assessable: cov.AssessableControls, Gaps: cov.Gaps,
			})
		}
	}
	writeJSON(w, http.StatusOK, view)
}

// tenantHasCompletedScan reports whether any scan has actually finished for this tenant — the
// evidence behind the public "continuously monitored" claim.
//
// A completed engagement is the same signal coverage.Compute and the readiness checklist read, so
// the public page cannot disagree with what the customer sees in-app. Adding an asset is not being
// monitored; a scan finishing is.
func (d Deps) tenantHasCompletedScan(ctx context.Context, tenantID string) bool {
	engs, err := d.Store.ListEngagements(ctx, tenantID)
	if err != nil {
		return false // cannot prove it, so do not claim it
	}
	for _, e := range engs {
		if !e.CompletedAt.IsZero() {
			return true
		}
	}
	return false
}

// tenantHasSignedDecisions reports whether there is a signed decision trail for this tenant.
//
// Every Action is recorded into the ledger when it is proposed or decided, so the existence of one
// is the evidence that this workspace has signed history — as opposed to the platform merely being
// CAPABLE of signing, which is what the badge would otherwise be asserting on an empty workspace.
func (d Deps) tenantHasSignedDecisions(ctx context.Context, tenantID string) bool {
	acts, err := d.Store.ListActions(ctx, tenantID)
	if err != nil {
		return false
	}
	return len(acts) > 0
}
