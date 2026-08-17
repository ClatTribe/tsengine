package connector

import (
	"fmt"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The WRITE scopes the identity mutations need. Every IdP here onboards READ-ONLY by design, so a
// suspend/disable fails until an admin re-consents with the write scope. That is knowable from the
// connection's recorded grants, which means the human can be told BEFORE they approve instead of
// watching the provider return 403 afterwards.
const (
	oktaWriteScope       = "okta.users.manage"
	gworkspaceWriteScope = "https://www.googleapis.com/auth/admin.directory.user"
	m365WriteScope       = "User.ReadWrite.All"
)

// missingWriteScope reports a KNOWN blocker when the connection's recorded grants do not include the
// scope a write needs.
//
// Grounded (§10) in two ways that matter:
//   - An EMPTY scope list is UNKNOWN, not "missing". Some connections never record grants, and
//     claiming a blocker we cannot prove would train people to ignore the warning.
//   - The match is EXACT, never a prefix/substring. Google's read scope
//     ("…/admin.directory.user.readonly") CONTAINS the write scope ("…/admin.directory.user"), so a
//     substring check would report read-only access as write-capable — the precise inversion of what
//     this exists to prevent.
func missingWriteScope(c platform.Connection, want, what string) error {
	if len(c.Scopes) == 0 {
		return nil // unknown → say nothing
	}
	for _, s := range c.Scopes {
		if s == want {
			return nil
		}
	}
	return fmt.Errorf("this connection holds read-only access: %s needs the %q scope, which an "+
		"administrator must grant before the fix can be applied", what, want)
}
