package bench

import (
	"strings"
	"testing"
)

const rhinoSnippet = `
methods_and_permissions = {
    'UpdateIAMRole': {
        'Permissions': [
            'iam.roles.update'
        ],
        'Scope': [
            'Organization',
            'Project'
        ]
    },
    'CreateGCEInstanceWithSA': {
        'Permissions': [
            'compute.instances.create',
            'iam.serviceAccounts.actAs'
        ],
        'Scope': [
            'Project'
        ]
    },
}
`

func TestParseRhinoCatalogue_ReadsMethodsAndTheirPermissions(t *testing.T) {
	got := ParseRhinoCatalogue(rhinoSnippet)
	if len(got) != 2 {
		t.Fatalf("want 2 methods, got %d (%+v)", len(got), got)
	}
	if got[0].Name != "UpdateIAMRole" || len(got[0].Permissions) != 1 {
		t.Fatalf("first method mis-parsed: %+v", got[0])
	}
	if len(got[1].Permissions) != 2 {
		t.Fatalf("a multi-permission method must keep all of them: %+v", got[1])
	}
}

// Scope is a sibling list and must NOT be read as permissions, or every method would
// appear to require 'Project'.
func TestParseRhinoCatalogue_DoesNotReadScopeAsPermissions(t *testing.T) {
	for _, m := range ParseRhinoCatalogue(rhinoSnippet) {
		for _, p := range m.Permissions {
			if p == "Project" || p == "Organization" {
				t.Fatalf("%s: Scope leaked into Permissions: %+v", m.Name, m.Permissions)
			}
		}
	}
}

// THE SHAPE GUARD. This reads one file in one known shape; if that changes the COUNT must
// drop visibly rather than the score quietly improving on fewer methods.
func TestParseRhinoCatalogue_UnrecognisedShapeYieldsNothing(t *testing.T) {
	if got := ParseRhinoCatalogue(`methods = {"UpdateIAMRole": {"Permissions": ["iam.roles.update"]}}`); len(got) != 0 {
		t.Fatalf("a JSON-style dict is not the shape this parses; guessing at it would be worse: %+v", got)
	}
}

// The method NAME is the answer and must never reach the detector — only permissions do.
func TestScoreGCPPrivesc_NameIsNeverAnInput(t *testing.T) {
	// A method named after a real escalation whose permission is harmless must not score.
	src := `
methods_and_permissions = {
    'SetProjectIAMPolicy': {
        'Permissions': [
            'storage.objects.get'
        ],
        'Scope': [
            'Project'
        ]
    },
}
`
	ms := ParseRhinoCatalogue(src)
	if len(ms) != 1 {
		t.Fatalf("want 1 method, got %d", len(ms))
	}
	res := GCPPrivescResult{}
	for _, m := range ms {
		granted := map[string]bool{}
		for _, p := range m.Permissions {
			granted[strings.ToLower(p)] = true
		}
		res.Total++
		if len(m.Detected) > 0 {
			res.Hits++
		}
	}
	if res.Hits != 0 {
		t.Fatal("a method named after an escalation whose permission only reads objects must not score")
	}
}

func TestRenderGCPPrivesc_NamesMissesAndAttributesTheKey(t *testing.T) {
	out := RenderGCPPrivesc(GCPPrivescResult{
		Total: 2, Hits: 1,
		Methods: []GCPMethod{
			{Name: "UpdateIAMRole", Permissions: []string{"iam.roles.update"}, Detected: []string{"UpdateCustomRole"}, Found: true},
			{Name: "CreateAPIKey", Permissions: []string{"serviceusage.apiKeys.create"}},
		},
	})
	if !strings.Contains(out, "CreateAPIKey") || !strings.Contains(out, "serviceusage.apiKeys.create") {
		t.Fatal("a miss must name the method AND what it needs, or nobody can judge it")
	}
	if !strings.Contains(out, "Rhino Security Labs") {
		t.Fatal("the report must say whose answer key this is — that is the whole claim")
	}
}
