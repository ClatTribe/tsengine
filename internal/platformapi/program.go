package platformapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// program.go is the security-program (vCISO) API — the policy register + acknowledgments. The engine
// can SEED the standard policy set, but PUBLISHING a policy is a named owner's judgment act (HITL) and
// each member's ACKNOWLEDGMENT names the person. Both are signed into the ledger.

func (d Deps) handleListProgram(w http.ResponseWriter, r *http.Request, tenantID string) {
	policies, err := d.Store.ListPolicies(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Category != policies[j].Category {
			return policies[i].Category < policies[j].Category
		}
		return policies[i].Name < policies[j].Name
	})
	teamSize := 0
	if users, err := d.Store.ListUsers(r.Context(), tenantID); err == nil {
		teamSize = len(users)
	}
	if policies == nil {
		policies = []platform.Policy{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies, "summary": grc.SummarizeProgram(policies, teamSize)})
}

// handleSeedProgram seeds the standard policy set as drafts. It upserts ONLY policies whose id does
// not already exist — an adopted/edited/published policy is never overwritten by a re-seed.
func (d Deps) handleSeedProgram(w http.ResponseWriter, r *http.Request, tenantID string) {
	existing, err := d.Store.ListPolicies(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	have := map[string]bool{}
	for _, p := range existing {
		have[p.ID] = true
	}
	seeded := make([]platform.Policy, 0)
	for _, p := range grc.StarterPolicies(tenantID, time.Now().UTC()) {
		if have[p.ID] {
			continue
		}
		if err := d.Store.PutPolicy(r.Context(), p); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		seeded = append(seeded, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"seeded": seeded, "count": len(seeded)})
}

// handlePublishPolicy is the HITL: a named owner publishes a policy (a judgment act), signed into the
// ledger. owner is required.
func (d Deps) handlePublishPolicy(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Owner string `json:"owner"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	// the tenant path resolves the publisher's capacity from the roster by their typed name
	cap, firm := d.practitionerCapacity(r, tenantID, strings.TrimSpace(body.Owner))
	p, status, err := d.applyPolicyPublish(r, tenantID, r.PathValue("id"), body.Owner, cap, firm)
	if err != nil {
		writeJSON(w, status, errBody(err.Error()))
		return
	}
	writeJSON(w, status, p)
}

// applyPolicyPublish publishes a policy as a NAMED human act and signs it into the ledger. Shared by
// the tenant-session path (handlePublishPolicy) and the operator act-on-behalf path
// (handleOperatorPublishPolicy) — they differ only in how capacity/firm are resolved (typed name vs.
// the operator's roster record). Returns the published policy, or an HTTP status + error to render.
func (d Deps) applyPolicyPublish(r *http.Request, tenantID, id, owner, capacity, firm string) (platform.Policy, int, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return platform.Policy{}, http.StatusBadRequest, errors.New("a named owner is required to publish a policy")
	}
	p, ok := d.findPolicy(r, tenantID, id)
	if !ok {
		return platform.Policy{}, http.StatusNotFound, errors.New("policy not found")
	}
	p.Owner = owner
	p.Capacity, p.Firm = capacity, firm // who the publisher works for
	p.Status = platform.PolicyPublished
	p.PublishedAt = time.Now().UTC()
	if d.Recorder != nil {
		d.Recorder.Record("security policy published (human)", "policy_publish",
			map[string]any{"tenant_id": tenantID, "policy_id": p.ID, "owner": owner, "capacity": p.Capacity}, "policy "+p.Name+" published by "+owner)
		p.LedgerRef = "policy-published-" + p.ID
	}
	if err := d.Store.PutPolicy(r.Context(), p); err != nil {
		return platform.Policy{}, http.StatusInternalServerError, err
	}
	return p, http.StatusOK, nil
}

// handleAckPolicy records that a named user acknowledged a published policy (the read-and-accept
// evidence). user is required (the frontend supplies the authenticated user). Idempotent per user.
func (d Deps) handleAckPolicy(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		User string `json:"user"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	user := strings.TrimSpace(body.User)
	if user == "" {
		writeJSON(w, http.StatusBadRequest, errBody("the acknowledging user is required"))
		return
	}
	p, ok := d.findPolicy(r, tenantID, r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("policy not found"))
		return
	}
	if p.Status != platform.PolicyPublished {
		writeJSON(w, http.StatusBadRequest, errBody("only a published policy can be acknowledged"))
		return
	}
	if !p.AckedBy(user) { // idempotent: one ack per user
		p.Acks = append(p.Acks, platform.PolicyAck{User: user, AckedAt: time.Now().UTC()})
		if err := d.Store.PutPolicy(r.Context(), p); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
	}
	writeJSON(w, http.StatusOK, p)
}

func (d Deps) findPolicy(r *http.Request, tenantID, id string) (platform.Policy, bool) {
	ps, err := d.Store.ListPolicies(r.Context(), tenantID)
	if err != nil {
		return platform.Policy{}, false
	}
	for _, p := range ps {
		if p.ID == id {
			return p, true
		}
	}
	return platform.Policy{}, false
}
