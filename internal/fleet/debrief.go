package fleet

import (
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// surfaceWeb is the estategraph surface a web worker's routes project into, so worldview routes and
// estate nodes share ONE identity space (ADR 0030 D1) from Phase A — cheap now, expensive to retrofit.
const surfaceWeb = "web"

// ClaimsFromFindings projects a web engagement's grounded findings into worldview claims.
//
// In Phase A this is the SOLE claim source, deliberately. Only a recorded finding carries both a
// class label and cited evidence turns (webagent's requiredIndicator gate already refused any
// finding whose cited turn lacks the class's indicator), so a finding → a Vulnerable verdict per
// (route, class) is fully grounded. The route is Canonicalized into estategraph's identity space.
//
// Clean and Denied per-class are NOT synthesized here: they need a KNOWN attempt scope — which class
// was tried against which route — and a raw non-finding turn does not carry one. Reading "no finding
// on a route the worker passed through" as Clean is the exact absence-as-evidence overclaim the
// ledger exists to prevent (§10). Those verdicts become groundable when a chunk defines the attempt
// (Phase B); until then a route with no proven class is reported as "no verdict", never clean.
func ClaimsFromFindings(findings []webagent.Finding) []Claim {
	var claims []Claim
	for _, f := range findings {
		ev := nonEmpty(f.Evidence)
		if len(ev) == 0 || f.Route == "" || f.Class == "" {
			continue // no cited evidence / unlabeled → cannot enter (Update would refuse it anyway)
		}
		claims = append(claims, Claim{
			Route:    routeID(f.Route),
			Class:    f.Class,
			Verdict:  Vulnerable,
			Evidence: ev,
		})
	}
	return claims
}

// CanonicalRoutes projects a worker's known-route list into the shared identity space, deduped and
// sorted — the surface the ledger measures "established vs untried" against.
func CanonicalRoutes(routes []string) []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		if r == "" {
			continue
		}
		out = append(out, routeID(r))
	}
	return sortUnique(out)
}
