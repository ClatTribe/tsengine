package platformapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/pkg/platform"
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
	Coverage  int    `json:"coverage"` // % of controls met
	Met       int    `json:"met"`
	Total     int    `json:"total"`
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
	view := trustView{Org: t.Name, Monitored: true, Signed: true, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	if d.GRC != nil {
		for _, fw := range trustFrameworks {
			cs, err := d.GRC.Posture(r.Context(), tenant, fw)
			if err != nil || len(cs) == 0 {
				continue
			}
			met := 0
			for _, c := range cs {
				if c.State != platform.ControlGap {
					met++
				}
			}
			view.Frameworks = append(view.Frameworks, trustFramework{
				Framework: fw, Met: met, Total: len(cs), Coverage: met * 100 / len(cs),
			})
		}
	}
	writeJSON(w, http.StatusOK, view)
}
