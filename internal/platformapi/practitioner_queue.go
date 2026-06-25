package platformapi

import (
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/practitioner"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// practitioner_queue.go is the cross-tenant practitioner DESK — the single queue an expert (the MSP's
// or our managed delivery expert) works across their book of client tenants. It is an OPERATOR
// capability, gated by the platform token (d.platformAuth), NOT a tenant session — so it never
// broadens tenant isolation for tenant users. It aggregates only the tenants where the named
// practitioner is in the roster, scoped to their deliverables.

// handlePractitionerQueue returns the pending HITL items for ?practitioner=<email-or-name> across the
// tenants that named them a practitioner of record. Operator-platform-token gated.
func (d Deps) handlePractitionerQueue(w http.ResponseWriter, r *http.Request) {
	who := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("practitioner")))
	if who == "" {
		writeJSON(w, http.StatusBadRequest, errBody("practitioner (email or name) query param is required"))
		return
	}
	resp, err := d.practitionerQueue(r, who)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// practitionerQueue aggregates the pending HITL items for a practitioner (by email or name) across the
// tenants whose roster names them — and ONLY those tenants. Shared by the platform-token endpoint and
// the operator-session console. Reads a tenant only when the practitioner is assigned to it, so tenant
// isolation (§18.2 inv. 2) holds.
func (d Deps) practitionerQueue(r *http.Request, who string) (map[string]any, error) {
	who = strings.ToLower(strings.TrimSpace(who))
	ctx := r.Context()
	tenants, err := d.Store.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	var data []practitioner.TenantData
	served := 0
	for _, t := range tenants {
		p, ok := matchPractitioner(t, who)
		if !ok {
			continue // the practitioner is not assigned to this tenant — never read it
		}
		served++
		td := practitioner.TenantData{TenantID: t.ID, TenantName: tenantLabel(t), Scope: p.Scope}
		td.Risks, _ = d.Store.ListRisks(ctx, t.ID)
		td.Audits, _ = d.Store.ListAuditEngagements(ctx, t.ID)
		td.Pentests, _ = d.Store.ListPentests(ctx, t.ID)
		td.Policies, _ = d.Store.ListPolicies(ctx, t.ID)
		data = append(data, td)
	}
	items := practitioner.Queue(data)
	if items == nil {
		items = []practitioner.Pending{}
	}
	byKind := map[string]int{}
	for _, it := range items {
		byKind[it.Kind]++
	}
	return map[string]any{
		"practitioner":   who,
		"tenants_served": served,
		"count":          len(items),
		"by_kind":        byKind,
		"items":          items,
	}, nil
}

// matchPractitioner finds the practitioner of record in a tenant's roster by email or name.
func matchPractitioner(t platform.Tenant, who string) (platform.Practitioner, bool) {
	for _, p := range t.Practitioners {
		if strings.ToLower(p.Name) == who || (p.Email != "" && strings.ToLower(p.Email) == who) {
			return p, true
		}
	}
	return platform.Practitioner{}, false
}

func tenantLabel(t platform.Tenant) string {
	if t.Name != "" {
		return t.Name
	}
	return t.ID
}
