package connector

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Google's READ scope contains the WRITE scope as a prefix. A substring check would report a
// read-only connection as write-capable — the exact inversion of what the preflight is for.
func TestMissingWriteScope_ReadonlyIsNotMistakenForWrite(t *testing.T) {
	ro := platform.Connection{Scopes: []string{"https://www.googleapis.com/auth/admin.directory.user.readonly"}}
	err := missingWriteScope(ro, gworkspaceWriteScope, "suspending a user")
	if err == nil {
		t.Fatal("a read-only Workspace grant was accepted as write-capable")
	}
	if !strings.Contains(err.Error(), "admin.directory.user") {
		t.Errorf("the blocker should name the scope to grant, got %q", err)
	}
	rw := platform.Connection{Scopes: []string{gworkspaceWriteScope}}
	if err := missingWriteScope(rw, gworkspaceWriteScope, "suspending a user"); err != nil {
		t.Errorf("a granted write scope was reported blocked: %v", err)
	}
}

// An unrecorded scope list is UNKNOWN, not missing — claiming a blocker we cannot prove would be
// noise, and noise trains people to click past warnings.
func TestMissingWriteScope_UnknownScopesClaimNothing(t *testing.T) {
	if err := missingWriteScope(platform.Connection{}, oktaWriteScope, "suspending a user"); err != nil {
		t.Errorf("an empty scope list produced a blocker: %v", err)
	}
}

// End to end for the real-world case: a Workspace connection onboarded read-only (which is the
// DEFAULT — every IdP here onboards read-only by design) must warn before approval, and must refuse
// the apply for the same reason. The two paths share one validator so they cannot disagree.
func TestIdentityPreflight_ReadonlyConnectionWarnsAndRefuses(t *testing.T) {
	act := platform.Action{ID: "a1", Kind: platform.ActApplyConfig,
		Payload: map[string]any{"remediation_type": "account_suspend", "target": "leaver@acme.com"}}

	for _, tc := range []struct {
		name  string
		conn  platform.Connection
		pre   func(platform.Connection, platform.Action) error
		apply func(platform.Connection, platform.Action) error
	}{
		{
			name: "gworkspace",
			conn: platform.Connection{Scopes: []string{"https://www.googleapis.com/auth/admin.directory.user.readonly"}},
			pre:  (&GWorkspace{}).Preflight,
			apply: func(c platform.Connection, a platform.Action) error {
				return (&GWorkspace{}).Apply(context.Background(), c, "tok", a)
			},
		},
		{
			name: "m365",
			conn: platform.Connection{Scopes: []string{"User.Read.All"}},
			pre:  (&M365{}).Preflight,
			apply: func(c platform.Connection, a platform.Action) error {
				return (&M365{}).Apply(context.Background(), c, "tok", a)
			},
		},
		{
			name: "okta",
			conn: platform.Connection{Scopes: []string{"okta.users.read"}},
			pre:  (&Okta{}).Preflight,
			apply: func(c platform.Connection, a platform.Action) error {
				return (&Okta{}).Apply(context.Background(), c, "tok", a)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.pre(tc.conn, act); err == nil {
				t.Fatal("a read-only connection reported NO blocker — the customer approves a suspend that will 403")
			}
			// And the apply must refuse for the same reason rather than firing a doomed request.
			if err := tc.apply(tc.conn, act); err == nil {
				t.Error("apply proceeded despite the known blocker")
			}
		})
	}
}
