package api

import "strings"

// Per-method routing — the api analog of the web "don't run every tool on
// every URL" rule. Passing the whole spec inventory to every specialist is
// strix's iter-Q5.40 waste trap ("BOLA fires on POST /users with no
// resource id; BFLA fires on GET /health; mass_assignment fires on DELETE
// /sessions"). classifyOp routes each operation to the probe class that
// can actually find a bug there.
//
// The BOLA/BFLA/mass_assignment SPECIALISTS aren't built — there is no
// strong standalone OSS for API authz logic (strix built them in-house;
// tsengine's §13 forbids that without an ADR — Akto is the OSS candidate
// under evaluation). This classifier is pre-declared the way deps.go
// pre-declared auth dependencies: the routing is correct the day those
// tools land. Today it drives endpoint selection + tagging.

// Probe classes.
const (
	ProbeIDOR           = "idor"            // GET on a resource-id path
	ProbeBFLA           = "bfla"            // state-changing method (authz bypass)
	ProbeMassAssignment = "mass_assignment" // body-bearing create/update
	ProbeGeneric        = "generic"         // everything else (signature scan)
)

// classifyOp routes a (method, path) operation to its probe class.
func classifyOp(method, path string) string {
	m := strings.ToUpper(method)
	hasID := pathHasResourceID(path)
	switch m {
	case "GET", "HEAD":
		if hasID {
			return ProbeIDOR // object-level authz (OWASP API1)
		}
		return ProbeGeneric
	case "DELETE":
		return ProbeBFLA // function-level authz; nothing to mass-assign
	case "POST", "PUT", "PATCH":
		// Body-bearing writes are mass-assignment candidates (API3); they're
		// also BFLA candidates, but mass_assignment is the tighter route.
		return ProbeMassAssignment
	default:
		return ProbeGeneric
	}
}

// pathHasResourceID reports whether a path carries a resource identifier
// segment — an OpenAPI template param ("/users/{id}") or a trailing
// numeric/uuid-shaped segment. These are the IDOR/BOLA candidates.
func pathHasResourceID(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			return true
		}
	}
	return false
}

// splitOp parses a "METHOD url" surface entry. ok=false for entries that
// aren't operations (e.g. the bare target or the SPEC marker).
func splitOp(entry string) (method, url string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(entry), " ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	m := strings.ToUpper(parts[0])
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return m, strings.TrimSpace(parts[1]), true
	}
	return "", "", false
}
