package platformapi

import (
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
	// Frameworks starts as a non-nil empty slice so it serializes as [] not null when the tenant
	// has no posture data yet (the common fresh-tenant case) — a null would crash the PUBLIC
	// Trust Center page's .map (the Go nil-slice → JSON-null footgun, on a customer-shared URL).
	view := trustView{Org: t.Name, Monitored: true, Signed: true, Frameworks: []trustFramework{}, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
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
