package platformapi

import (
	"net/http"
	"strings"
)

// employee_scope.go is the allowlist that makes RoleEmployee usable.
//
// WHY AN ALLOWLIST. A denylist would leave every endpoint added after today exposed to the whole
// company by default, and whoever adds it has no reason to be thinking about employees. Closed by
// default means the failure mode is a colleague seeing "not for your account" on a page they did not
// need — recoverable, and visible. The other direction leaks the pentest report to everyone who was
// asked to do their training, silently, months later.
//
// WHAT AN EMPLOYEE MAY REACH is exactly the two things we ask of them — their training and their
// policy acknowledgements — plus the account endpoints everyone needs to sign in and change their
// own password. Nothing about the estate: no findings, no attack paths, no pentest, no settings, no
// system-state (which names how the security posture is degraded).
//
// Note POST /v1/training/record is NOT here. Recording that a COLLEAGUE was trained elsewhere is an
// administrative act about somebody else, and the whole point of the tier split is that a
// second-hand claim is entered by someone accountable for it.
var employeeAllowed = []struct {
	method, path string
}{
	{http.MethodGet, "/v1/training"},           // the curriculum, and what they owe
	{http.MethodPost, "/v1/training/complete"}, // confirming they read a module — about themselves only
	{http.MethodGet, "/v1/program"},            // the policies they are asked to acknowledge
	{http.MethodPost, "/v1/program/ack"},       // prefix — /v1/program/{id}/ack
}

// employeeMayReach reports whether an employee seat may make this request.
//
// The program-ack route carries an id in the middle, so it is matched by prefix + suffix rather than
// exactly. That is the only pattern match here on purpose: a general "starts with /v1/program"
// would also admit publishing a policy, which is an owner's act.
func employeeMayReach(method, path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, a := range employeeAllowed {
		if a.method != method {
			continue
		}
		if a.path == "/v1/program/ack" {
			if strings.HasPrefix(path, "/v1/program/") && strings.HasSuffix(path, "/ack") {
				return true
			}
			continue
		}
		if a.path == path {
			return true
		}
	}
	return false
}
