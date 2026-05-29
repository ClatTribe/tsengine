package web

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/dalfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	_ "github.com/ClatTribe/tsengine/internal/tool/seedauth"
	_ "github.com/ClatTribe/tsengine/internal/tool/sqlmap"
)

// With Auth set, PlanFanout must prepend a single seed_auth dispatch
// carrying the credentials, and it must lead the dispatch set (wave 0).
func TestPlanFanout_PrependsSeedAuthWhenAuthSet(t *testing.T) {
	h := NewHandler()
	target := types.Asset{
		Type:   types.AssetWebApplication,
		Target: "https://x/",
		Auth: &types.AuthConfig{
			LoginURL: "https://x/login",
			Username: "alice",
			Password: "s3cret",
		},
	}
	surface := []string{"https://x/", "https://x/search?q=1"}
	out := h.PlanFanout(target, surface)

	if len(out) == 0 {
		t.Fatal("PlanFanout returned nothing")
	}
	if out[0].Tool.Name() != "seed_auth" {
		t.Fatalf("first dispatch = %q, want seed_auth leading", out[0].Tool.Name())
	}
	// Exactly one seed_auth dispatch.
	n := 0
	for _, d := range out {
		if d.Tool.Name() == "seed_auth" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("seed_auth dispatches = %d, want exactly 1", n)
	}
	// Credentials threaded onto the dispatch args.
	args := out[0].Args
	if args["login_url"] != "https://x/login" || args["username"] != "alice" || args["password"] != "s3cret" {
		t.Fatalf("seed_auth args missing credentials: %#v", args)
	}
}

// A provided cookie also triggers seed_auth (passthrough mode).
func TestPlanFanout_SeedAuthCookiePassthrough(t *testing.T) {
	h := NewHandler()
	target := types.Asset{
		Type:   types.AssetWebApplication,
		Target: "https://x/",
		Auth:   &types.AuthConfig{Cookie: "session=abc"},
	}
	out := h.PlanFanout(target, []string{"https://x/"})
	if len(out) == 0 || out[0].Tool.Name() != "seed_auth" {
		t.Fatal("expected seed_auth to lead with a provided cookie")
	}
	if out[0].Args["cookie"] != "session=abc" {
		t.Fatalf("seed_auth cookie arg = %v, want session=abc", out[0].Args["cookie"])
	}
}

// No Auth → no seed_auth dispatch (unauthenticated scan, zero overhead).
func TestPlanFanout_NoSeedAuthWithoutAuth(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetWebApplication, Target: "https://x/"}
	out := h.PlanFanout(target, []string{"https://x/"})
	for _, d := range out {
		if d.Tool.Name() == "seed_auth" {
			t.Fatal("seed_auth should not fire when Auth is nil")
		}
	}
}

// Guard: seed_auth must actually be registered for the prepend to resolve.
func TestSeedAuthRegistered(t *testing.T) {
	if _, ok := tool.Get("seed_auth"); !ok {
		t.Fatal("seed_auth not in registry — PlanFanout prepend would silently no-op")
	}
}
