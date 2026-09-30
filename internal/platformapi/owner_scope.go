package platformapi

import (
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// owner_scope.go is what separates the workspace OWNER from an invited MEMBER on the server.
//
// WHY THIS EXISTS. The Settings page showed the kill-switch and connection quarantine only to the owner,
// and nothing else did: every one of these endpoints accepted a member's session. Hiding a button is
// cosmetic — the request that matters is the hand-crafted one — so a member could resume automation the
// owner had halted, silence alerting with a maintenance window, point incident alerts at a different
// Slack, or release the penetration-test report to a stranger, and the UI's gating recorded none of it
// as a refusal. The auditor and employee seats were already enforced at the one gate every app
// endpoint shares; the member/owner line was the one left to the frontend.
//
// THE RULE: a member may make the workspace MORE cautious; only the owner may make it LESS cautious, or
// change who and what it trusts. So a member can halt automation, quarantine a connection, mark a
// finding a false positive, end a maintenance window or remove an exclusion — each stops something or
// shows something. Resuming, restoring, accepting a risk, suppressing a class of findings, and every
// setting are the owner's. Members keep the day-to-day work: triage, approvals, scans, investigations.
//
// TWO MECHANISMS, because some acts are the same route in both directions. A route that is owner-only
// whatever its body is refused HERE, in the middleware (ownerOnlyRoute). A route whose direction lives
// in the body — halt vs resume, quarantine vs restore, false positive vs accepted risk — checks
// callerIsOwner inside the handler, at the point the direction is known. Both are covered by tests.
//
// SETTINGS ARE A PREFIX, on purpose. A new /v1/settings/* endpoint is owner-only the day it is added,
// because whoever adds it has no reason to be thinking about members; the failure mode of a prefix is
// a member told "ask your workspace owner", which is visible and recoverable.

// ownerOnlyRoutes are refused to every seat but the owner's, whatever the request body says. Paths use
// the mux's {name} wildcard; a segment in braces matches any single segment.
var ownerOnlyRoutes = []struct {
	method, path string
}{
	// Connections: removing one, or granting the platform a cloud WRITE role. (Quarantine is
	// direction-dependent — see handleQuarantineConnection.)
	{http.MethodDelete, "/v1/connections/{id}"},
	{http.MethodPost, "/v1/connections/{id}/cloud-remediation"},

	// Who is accountable and who gets paged. Editing the escalation roster redirects the page for the
	// next critical incident; the practitioner roster decides whose HITL signature counts.
	{http.MethodPost, "/v1/practitioners"},
	{http.MethodDelete, "/v1/practitioners/{id}"},
	{http.MethodPost, "/v1/contacts"},
	{http.MethodDelete, "/v1/contacts/{id}"},

	// A maintenance window SUPPRESSES new incidents and escalation while it runs. Scheduling one is an
	// owner's act; ending one early (DELETE) makes the workspace more cautious, so a member may.
	{http.MethodPost, "/v1/maintenance-windows"},

	// Releasing a gated Trust Center document — a pentest report, an evidence pack — to a stranger.
	{http.MethodPost, "/v1/trust-requests/{id}/decision"},

	// Suppression of a whole CLASS of findings before they become issues. Removing a rule restores
	// visibility, so /v1/exclusions/delete stays open to members.
	{http.MethodPost, "/v1/exclusions"},

	// What the compliance program is measured against, and the company's published policies.
	{http.MethodPost, "/v1/custom-frameworks"},
	{http.MethodDelete, "/v1/custom-frameworks/{id}"},
	{http.MethodPost, "/v1/program/{id}/publish"},

	// Scope: which assets make up a product the customer reports on, and what is out of scope.
	// Descoping an asset removes it from every exposure number the owner signs off on.
	{http.MethodPost, "/v1/products"},
	{http.MethodPut, "/v1/products/{id}"},
	{http.MethodDelete, "/v1/products/{id}"},
	{http.MethodPost, "/v1/products/scope"},
}

// ownerOnlyRoute reports whether this request may be made only by the workspace owner.
func ownerOnlyRoute(method, path string) bool {
	path = strings.TrimSuffix(path, "/")
	if strings.HasPrefix(path, "/v1/settings/") && !readOnlyMethod(method) {
		return true
	}
	for _, o := range ownerOnlyRoutes {
		if o.method == method && pathMatches(o.path, path) {
			return true
		}
	}
	return false
}

// pathMatches compares a mux pattern with {wildcard} segments against a concrete path, segment by
// segment. Exact length: /v1/products/{id} must not match /v1/products/x/y.
func pathMatches(pattern, path string) bool {
	ps, xs := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if strings.HasPrefix(ps[i], "{") && strings.HasSuffix(ps[i], "}") {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if ps[i] != xs[i] {
			return false
		}
	}
	return true
}

// callerIsOwner is the in-handler check for acts whose direction lives in the body. The platform
// bearer token is the operator's credential, above any tenant seat, so it passes; a session passes only
// when its user is the owner. An unreadable user FAILS — this gate refuses on doubt, because the act it
// guards is the one that makes the workspace less cautious.
func (d Deps) callerIsOwner(r *http.Request) bool {
	if d.bearerOK(r) {
		return true
	}
	s, ok := d.resolveSession(r)
	if !ok {
		return false
	}
	u, err := d.Store.GetUser(r.Context(), s.UserID)
	return err == nil && u.Role == platform.RoleOwner
}

// refuseOwnerOnly writes the one refusal every owner-only act returns, so the frontend can key on the
// code rather than parse prose.
func refuseOwnerOnly(w http.ResponseWriter, what string) {
	writeJSON(w, http.StatusForbidden, errCode(what+" — ask your workspace owner", "owner_only"))
}
