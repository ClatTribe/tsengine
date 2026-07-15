package remediate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func cfRepoAsset() platform.Asset {
	return platform.Asset{
		TenantID: "t1", Type: "repository", Target: "acme/app", ConnectionID: "c1",
		Meta: map[string]string{"full_name": "acme/app"},
	}
}

func cfSQLiFinding() types.Finding {
	return types.Finding{
		ID: "f-1", RuleID: "semgrep::sqli", Tool: "semgrep", Severity: types.SeverityHigh,
		CWE: []string{"CWE-89"}, Endpoint: "app/login.php:42", Title: "SQL injection in login",
	}
}

// TestProposeWithPatch_CarriesTheFiles: the patch must ride the action so the connector can commit it
// — this is the link that makes a fix PR contain a diff.
func TestProposeWithPatch_CarriesTheFiles(t *testing.T) {
	files := map[string]string{"app/login.php": "<?php // parameterised"}
	act, ok := ProposeWithPatch(cfSQLiFinding(), cfRepoAsset(), files, nil)
	if !ok {
		t.Fatal("want an action")
	}
	if act.Kind != platform.ActOpenPR {
		t.Fatalf("want ActOpenPR, got %v", act.Kind)
	}
	got, _ := act.Payload["files"].(map[string]any)
	if len(got) != 1 || got["app/login.php"] != "<?php // parameterised" {
		t.Errorf("files payload wrong: %#v", act.Payload["files"])
	}
	// the gate must be unchanged — a patch does not get a free pass
	base, _ := Propose(cfSQLiFinding(), cfRepoAsset(), nil)
	if act.Tier != base.Tier {
		t.Errorf("patch must not change the tier/gate: got %d want %d", act.Tier, base.Tier)
	}
	body, _ := act.Payload["body"].(string)
	for _, want := range []string{"app/login.php", "CWE-89", "semgrep::sqli", "Review the diff"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}

// TestProposeWithPatch_NoFilesFallsBackToProse: never claim a fix we don't carry.
func TestProposeWithPatch_NoFilesFallsBackToProse(t *testing.T) {
	act, ok := ProposeWithPatch(cfSQLiFinding(), cfRepoAsset(), nil, nil)
	if !ok {
		t.Fatal("want an action")
	}
	if _, has := act.Payload["files"]; has {
		t.Error("no patch → the action must not carry a files payload")
	}
	base, _ := Propose(cfSQLiFinding(), cfRepoAsset(), nil)
	if act.Payload["body"] != base.Payload["body"] {
		t.Error("no patch → body must be the unchanged prose body")
	}
}

// TestProposeWithPatch_NonRepoAssetUnchanged: a cloud finding has no PR shape; the patch path must not
// invent one.
func TestProposeWithPatch_NonRepoAssetUnchanged(t *testing.T) {
	cloud := platform.Asset{TenantID: "t1", Type: "cloud_account", Target: "111122223333", ConnectionID: "c2"}
	act, ok := ProposeWithPatch(cfSQLiFinding(), cloud, map[string]string{"a.tf": "x"}, nil)
	if ok && act.Kind == platform.ActOpenPR {
		t.Error("a cloud asset must not become a code PR")
	}
	if _, has := act.Payload["files"]; has {
		t.Error("non-repo action must not carry code files")
	}
}
