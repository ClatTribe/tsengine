// Package argcontract holds the cross-asset arg-contract CI guard (C4).
//
// strix passed tool args by bare string key with no contract, so a Handler
// that dispatched a tool with the wrong key ("url" instead of "target")
// had its args silently ignored — dropping 5+ anchor signals per target
// with no error, a pure recall loss invisible to scoring. This test makes
// that class of bug a LOUD build failure: for every asset Handler, every
// arg key it dispatches must be in the target tool's KnownArgs
// (tool.ArgSpec), and every dispatched tool must resolve in the registry.
//
// It lives in its own package so it can import every handler + every tool
// wrapper (blank imports register them) without an import cycle.
package argcontract

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"

	apiasset "github.com/ClatTribe/tsengine/internal/asset/api"
	cloudasset "github.com/ClatTribe/tsengine/internal/asset/cloud"
	containerasset "github.com/ClatTribe/tsengine/internal/asset/container"
	domainasset "github.com/ClatTribe/tsengine/internal/asset/domain"
	ipasset "github.com/ClatTribe/tsengine/internal/asset/ip"
	repoasset "github.com/ClatTribe/tsengine/internal/asset/repository"
	webasset "github.com/ClatTribe/tsengine/internal/asset/web"

	// Register every tool wrapper so the handlers resolve their anchors.
	_ "github.com/ClatTribe/tsengine/internal/tool/amass"
	_ "github.com/ClatTribe/tsengine/internal/tool/checkdmarc"
	_ "github.com/ClatTribe/tsengine/internal/tool/crtsh"
	_ "github.com/ClatTribe/tsengine/internal/tool/dalfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/dockle"
	_ "github.com/ClatTribe/tsengine/internal/tool/gitleaks"
	_ "github.com/ClatTribe/tsengine/internal/tool/grype"
	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/katana"
	_ "github.com/ClatTribe/tsengine/internal/tool/naabu"
	_ "github.com/ClatTribe/tsengine/internal/tool/nmap"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	_ "github.com/ClatTribe/tsengine/internal/tool/prowler"
	_ "github.com/ClatTribe/tsengine/internal/tool/seedauth"
	_ "github.com/ClatTribe/tsengine/internal/tool/semgrep"
	_ "github.com/ClatTribe/tsengine/internal/tool/sqlmap"
	_ "github.com/ClatTribe/tsengine/internal/tool/subfinder"
	_ "github.com/ClatTribe/tsengine/internal/tool/trivy"
	_ "github.com/ClatTribe/tsengine/internal/tool/trufflehog"
)

type assetCase struct {
	name    string
	handler asset.Handler
	target  types.Asset
	surface []string // for ReconHandler.PlanFanout
}

func cases() []assetCase {
	return []assetCase{
		{"web", webasset.NewHandler(),
			types.Asset{Type: types.AssetWebApplication, Target: "http://localhost:8080/",
				// Set Auth so PlanFanout also emits the seed_auth dispatch.
				Auth: &types.AuthConfig{LoginURL: "http://localhost:8080/login", Username: "u", Password: "p"}},
			[]string{"http://localhost:8080/", "http://localhost:8080/x?id=1"}},
		{"api", apiasset.NewHandler(),
			types.Asset{Type: types.AssetAPI, Target: "http://localhost:8080/"}, nil},
		{"domain", domainasset.NewHandler(),
			types.Asset{Type: types.AssetDomain, Target: "example.com"},
			[]string{"example.com", "a.example.com", "b.example.com"}},
		{"cloud", cloudasset.NewHandler(),
			types.Asset{Type: types.AssetCloudAccount, Target: "aws"}, nil},
		{"ip", ipasset.NewHandler(),
			types.Asset{Type: types.AssetIPAddress, Target: "127.0.0.1"},
			[]string{"127.0.0.1:80", "127.0.0.1:443"}},
		{"repository", repoasset.NewHandler(),
			types.Asset{Type: types.AssetRepository, Target: "/workspace"}, nil},
		{"container", containerasset.NewHandler(),
			types.Asset{Type: types.AssetContainerImage, Target: "nginx:latest"}, nil},
	}
}

// validate asserts a dispatch is well-formed: its tool resolves in the
// registry and every arg key is recognized by that tool.
func validate(t *testing.T, asetName string, d asset.Dispatch) {
	t.Helper()
	name := d.Tool.Name()
	if _, ok := tool.Get(name); !ok {
		t.Errorf("[%s] dispatched tool %q is not in the registry (mis-wired blank import?)", asetName, name)
	}
	for key := range d.Args {
		if !tool.ArgIsKnown(d.Tool, key) {
			t.Errorf("[%s] tool %q dispatched with unknown arg %q — add it to %s.KnownArgs or fix the Handler (strix's silent-recall-drop class)",
				asetName, name, key, name)
		}
	}
}

func TestArgContracts_AllHandlers(t *testing.T) {
	ctx := context.Background()
	for _, c := range cases() {
		// PlanAnchors path.
		for _, d := range c.handler.Filter(ctx, c.target, c.handler.PlanAnchors(c.target)) {
			validate(t, c.name, d)
		}
		// ReconPlanner: PlanRecon dispatches.
		if rp, ok := c.handler.(asset.ReconPlanner); ok {
			for _, d := range rp.PlanRecon(c.target) {
				validate(t, c.name, d)
			}
		}
		// ReconHandler: PlanFanout dispatches over a sample surface.
		if rh, ok := c.handler.(asset.ReconHandler); ok {
			for _, d := range c.handler.Filter(ctx, c.target, rh.PlanFanout(c.target, c.surface)) {
				validate(t, c.name, d)
			}
		}
	}
}

// Sanity: at least one handler must actually dispatch something, else the
// test is vacuously green (e.g. all tools failed to register).
func TestArgContracts_NotVacuous(t *testing.T) {
	total := 0
	for _, c := range cases() {
		total += len(c.handler.PlanAnchors(c.target))
	}
	if total == 0 {
		t.Fatal("no handler dispatched any anchor — tool registration is broken")
	}
}
