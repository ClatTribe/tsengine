package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// compliance_scope.go is the BEFORE-analysis scoping surface — the questions a consultant asks first:
// which framework(s) does the customer need, and which systems must they connect so we can actually
// assess them. Without it we'd analyze blind and risk a false-compliant read off a half-connected estate.

type complianceScopeBody struct {
	TargetFrameworks  []string                    `json:"target_frameworks"`
	ComplianceProfile *platform.ComplianceProfile `json:"compliance_profile"`
}

// handleGetComplianceScope (GET /v1/settings/compliance-scope) returns the tenant's declared scope plus
// the frameworks SUGGESTED by their applicability profile (so the UI can recommend a real scope).
func (d Deps) handleGetComplianceScope(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	prof := platform.ComplianceProfile{}
	if t.ComplianceProfile != nil {
		prof = *t.ComplianceProfile
	}
	targets := t.TargetFrameworks
	if targets == nil {
		targets = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target_frameworks":  targets,
		"compliance_profile": prof,
		"suggested":          grc.SuggestedFrameworks(prof),
	})
}

// handlePutComplianceScope (PUT /v1/settings/compliance-scope) stores the customer's target frameworks +
// applicability profile. Validated (unknown framework → 400) so the scope is always real (§10).
func (d Deps) handlePutComplianceScope(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	var body complianceScopeBody
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid body"))
		return
	}
	for _, f := range body.TargetFrameworks {
		if !grc.IsFramework(f) {
			writeJSON(w, http.StatusBadRequest, errBody("unknown framework: "+f))
			return
		}
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	t.TargetFrameworks = body.TargetFrameworks
	t.ComplianceProfile = body.ComplianceProfile
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	d.handleGetComplianceScope(w, r, tenantID)
}

// handleComplianceReadiness (GET /v1/compliance/readiness) is the connect-this-first checklist: for the
// tenant's target frameworks, which recommended integrations are connected vs missing — so the customer
// knows what to wire up BEFORE we (or they) read the posture as compliant.
func (d Deps) handleComplianceReadiness(w http.ResponseWriter, r *http.Request, tenantID string) {
	writeJSON(w, http.StatusOK, d.computeReadiness(r.Context(), tenantID))
}

// computeReadiness derives the connect-this-first checklist from the tenant's connections + assets +
// declared scope. Shared by the readiness endpoint and the advisor agent.
func (d Deps) computeReadiness(ctx context.Context, tenantID string) grc.ReadinessReport {
	t, _ := d.Store.GetTenant(ctx, tenantID)
	connected := map[string]bool{}

	conns, _ := d.Store.ListConnections(ctx, tenantID)
	for _, c := range conns {
		switch c.Kind {
		case platform.ConnGWorkspace, platform.ConnM365, platform.ConnOkta:
			connected["identity"] = true
			connected["email"] = true // operate derives the sending domains from the IdP
		case platform.ConnAWS, platform.ConnGCP, platform.ConnAzure:
			connected["cloud"] = true
		case platform.ConnGitHub, platform.ConnGitLab, platform.ConnBitbucket, platform.ConnAzureDevOps:
			connected["code"] = true
			if c.Kind == platform.ConnGitHub {
				connected["saas"] = true // GitHub-org SSPM rides the same connection
			}
		case platform.ConnSlack:
			connected["saas"] = true
		}
	}
	assets, _ := d.Store.ListAssets(ctx, tenantID)
	for _, a := range assets {
		switch a.Type {
		case "repository":
			connected["code"] = true
		case "cloud_account":
			connected["cloud"] = true
		case "domain":
			connected["email"] = true
		case "web_application", "api":
			connected["web_api"] = true
		case "workspace":
			connected["identity"] = true
			connected["email"] = true
		}
	}

	targets := t.TargetFrameworks
	if len(targets) == 0 && t.ComplianceProfile != nil {
		targets = grc.SuggestedFrameworks(*t.ComplianceProfile)
	}
	if targets == nil {
		targets = []string{}
	}
	return grc.ScopeReadiness(targets, connected)
}
