package remediate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// capGitHub is a GitHub-kind connector that records the action it was asked to apply, so the test
// can see the payload the delivery path handed to the connector — files or no files.
type capGitHub struct{ got platform.Action }

func (c *capGitHub) Kind() string                              { return platform.ConnGitHub }
func (c *capGitHub) OAuthURL(state, redirectURI string) string { return "" }
func (c *capGitHub) Exchange(context.Context, string, string) (platform.Connection, error) {
	return platform.Connection{}, nil
}
func (c *capGitHub) Discover(context.Context, platform.Connection, string) ([]platform.Asset, error) {
	return nil, nil
}
func (c *capGitHub) Watch(context.Context, platform.Connection, []byte) ([]connector.Trigger, error) {
	return nil, nil
}
func (c *capGitHub) Apply(_ context.Context, _ platform.Connection, _ string, a platform.Action) error {
	c.got = a
	return nil
}

type patchTokens struct{}

func (patchTokens) Resolve(context.Context, platform.Connection) (string, error) {
	return "gh-token", nil
}

func prAction() platform.Action {
	return platform.Action{ID: "a1", TenantID: "t1", FindingID: "f1", ConnectionID: "c1", Kind: platform.ActOpenPR, Tier: 1,
		Title: "tsengine: fix SQL injection", Payload: map[string]any{
			"full_name": "acme/shop", "base": "main", "head": "tsengine/fix-f1", "body": "## Fix\nParameterise the query.",
		}}
}

func patchDeliverer(t *testing.T, p Patcher) (*Deliverer, *capGitHub) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnActive, SecretRef: "sealed"})
	gh := &capGitHub{}
	return &Deliverer{Store: st, Connectors: connector.NewRegistry(gh), Tokens: patchTokens{}, Patcher: p}, gh
}

// THE DEFECT: the automated pipeline's PR carried no files, so connector.GitHub.Apply opened a PR
// with instructions and no diff. With a Patcher, the delivery attaches the engineer's files, a
// commit message, and a body that says a patch is attached and what it rests on.
func TestDeliverer_AttachesThePatchToTheCodeFixPR(t *testing.T) {
	var seen struct {
		action platform.Action
		conn   platform.Connection
		token  string
	}
	p := PatcherFunc(func(_ context.Context, a platform.Action, c platform.Connection, token string) (map[string]string, string, error) {
		seen.action, seen.conn, seen.token = a, c, token
		return map[string]string{"app/db.go": "package app // parameterised\n", "app/db_test.go": "package app // regression\n"},
			"Proposed by the engineer; a regression test rides along.", nil
	})
	d, gh := patchDeliverer(t, p)
	if err := d.Apply(context.Background(), prAction()); err != nil {
		t.Fatal(err)
	}
	if seen.action.ID != "a1" || seen.conn.ID != "c1" || seen.token != "gh-token" {
		t.Errorf("the patcher must receive the action, its connection and the resolved token: %+v %+v %q", seen.action.ID, seen.conn.ID, seen.token)
	}
	files, _ := gh.got.Payload["files"].(map[string]string)
	if len(files) != 2 || files["app/db.go"] == "" {
		t.Fatalf("the connector was handed no files — the PR would carry instructions only: %+v", gh.got.Payload)
	}
	if gh.got.Payload["patch_status"] != "attached" || gh.got.Payload["commit_message"] != "tsengine: fix SQL injection" {
		t.Errorf("payload: %+v", gh.got.Payload)
	}
	body, _ := gh.got.Payload["body"].(string)
	if !strings.Contains(body, "carries a patch") || !strings.Contains(body, "app/db.go") || !strings.Contains(body, "regression test") ||
		!strings.Contains(body, "Parameterise the query") {
		t.Errorf("the body must announce the patch, name the files, carry the note, and keep the instructions:\n%s", body)
	}
}

// A patcher that cannot produce a diff does not fail the delivery: the PR still opens with its
// instructions, and the body says why there is no patch. Silence here would read as a patch that
// somehow did not land.
func TestDeliverer_PatchFailureStillOpensThePRAndSaysWhy(t *testing.T) {
	p := PatcherFunc(func(context.Context, platform.Action, platform.Connection, string) (map[string]string, string, error) {
		return nil, "", errors.New("no AI model is configured for this workspace")
	})
	d, gh := patchDeliverer(t, p)
	if err := d.Apply(context.Background(), prAction()); err != nil {
		t.Fatalf("a patch failure must not block the PR: %v", err)
	}
	if _, has := gh.got.Payload["files"]; has {
		t.Error("no files must be attached on failure")
	}
	body, _ := gh.got.Payload["body"].(string)
	if gh.got.Payload["patch_status"] != "not_attached" || !strings.Contains(body, "No patch is attached") || !strings.Contains(body, "no AI model") {
		t.Errorf("the body must say no patch is attached and why:\n%s", body)
	}
	// An engineer that proposes nothing is the same outcome with its own reason.
	d2, gh2 := patchDeliverer(t, PatcherFunc(func(context.Context, platform.Action, platform.Connection, string) (map[string]string, string, error) {
		return nil, "", nil
	}))
	_ = d2.Apply(context.Background(), prAction())
	if body, _ := gh2.got.Payload["body"].(string); !strings.Contains(body, "proposed no file change") {
		t.Errorf("an empty proposal must be named as such:\n%s", body)
	}
}

// No Patcher (a deployment without one) and an action that already carries files are both left
// exactly as they were.
func TestDeliverer_NoPatcherOrExistingFilesLeavesTheActionAlone(t *testing.T) {
	d, gh := patchDeliverer(t, nil)
	_ = d.Apply(context.Background(), prAction())
	if _, has := gh.got.Payload["patch_status"]; has {
		t.Error("with no patcher the payload must be untouched")
	}
	called := false
	d2, gh2 := patchDeliverer(t, PatcherFunc(func(context.Context, platform.Action, platform.Connection, string) (map[string]string, string, error) {
		called = true
		return nil, "", nil
	}))
	a := prAction()
	a.Payload["files"] = map[string]string{"x.go": "already"}
	_ = d2.Apply(context.Background(), a)
	if called || gh2.got.Payload["files"].(map[string]string)["x.go"] != "already" {
		t.Error("an action that already carries files must not be re-patched")
	}
}
