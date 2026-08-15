package platformapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
)

// The public Trust Center (a shareable "we're secure" page, like Vanta/Drata trust pages).
// It exposes ONLY non-sensitive aggregates — the org name and per-framework coverage %.
// It NEVER exposes findings, endpoints, or which specific controls are gaps: a gap list is
// an attacker's roadmap. Access is gated by an HMAC share token so a tenant id alone can't
// enumerate it; the token is stateless (keyed by the platform secret), so no extra storage.

// trustFrameworks is the set surfaced on the public Trust Center — the full framework set
// (grc.Frameworks), so the public coverage page reflects everything the tenant has posture
// for, not a stale six. Frameworks with no control state are skipped at render time.
var trustFrameworks = grc.Frameworks

// trustToken derives a tenant's non-guessable Trust Center share token.
func (d Deps) trustToken(tenant string) string {
	mac := hmac.New(sha256.New, []byte(d.Token))
	mac.Write([]byte("trust-center:" + tenant))
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
	Org         string           `json:"org"`
	Monitored   bool             `json:"monitored"`
	Signed      bool             `json:"signed"`
	Frameworks  []trustFramework `json:"frameworks"`
	GeneratedAt string           `json:"generated_at"`
}

// handleTrustLink (authed, tenant-scoped) returns the caller's own Trust Center token so the
// UI can render a shareable link.
func (d Deps) handleTrustLink(w http.ResponseWriter, r *http.Request, tenantID string) {
	tok := d.trustToken(tenantID)
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
	token := r.URL.Query().Get("token")
	if tenant == "" || token == "" || !hmac.Equal([]byte(token), []byte(d.trustToken(tenant))) {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenant)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return
	}
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
		Org:       t.Name,
		Monitored: d.tenantHasCompletedScan(r.Context(), tenant),
		Signed:    d.tenantHasSignedDecisions(r.Context(), tenant),
		// Non-nil empty slice so it serializes as [] not null on a tenant with no posture yet — a
		// null would crash the PUBLIC page's .map (the Go nil-slice → JSON-null footgun, on a URL
		// the customer shares with their own customers).
		Frameworks:  []trustFramework{},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
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
