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
	mobileasset "github.com/ClatTribe/tsengine/internal/asset/mobile"
	repoasset "github.com/ClatTribe/tsengine/internal/asset/repository"
	webasset "github.com/ClatTribe/tsengine/internal/asset/web"

	// Register every tool wrapper so the handlers resolve their anchors.
	_ "github.com/ClatTribe/tsengine/internal/tool/amass"
	_ "github.com/ClatTribe/tsengine/internal/tool/checkdmarc"
	_ "github.com/ClatTribe/tsengine/internal/tool/checkov"
	_ "github.com/ClatTribe/tsengine/internal/tool/cloudfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/codeql"
	_ "github.com/ClatTribe/tsengine/internal/tool/cosign"
	_ "github.com/ClatTribe/tsengine/internal/tool/crtsh"
	_ "github.com/ClatTribe/tsengine/internal/tool/dalfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/dnstwist"
	_ "github.com/ClatTribe/tsengine/internal/tool/dockle"
	_ "github.com/ClatTribe/tsengine/internal/tool/ffuf"
	_ "github.com/ClatTribe/tsengine/internal/tool/gitleaks"
	_ "github.com/ClatTribe/tsengine/internal/tool/govulncheck"
	_ "github.com/ClatTribe/tsengine/internal/tool/grype"
	_ "github.com/ClatTribe/tsengine/internal/tool/hadolint"
	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/hydra"
	_ "github.com/ClatTribe/tsengine/internal/tool/inql"
	_ "github.com/ClatTribe/tsengine/internal/tool/katana"
	_ "github.com/ClatTribe/tsengine/internal/tool/kiterunner"
	_ "github.com/ClatTribe/tsengine/internal/tool/mobsfscan"
	_ "github.com/ClatTribe/tsengine/internal/tool/naabu"
	_ "github.com/ClatTribe/tsengine/internal/tool/nmap"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	_ "github.com/ClatTribe/tsengine/internal/tool/openapi"
	_ "github.com/ClatTribe/tsengine/internal/tool/osvscanner"
	_ "github.com/ClatTribe/tsengine/internal/tool/prowler"
	_ "github.com/ClatTribe/tsengine/internal/tool/schemathesis"
	_ "github.com/ClatTribe/tsengine/internal/tool/scoutsuite"
	_ "github.com/ClatTribe/tsengine/internal/tool/seedauth"
	_ "github.com/ClatTribe/tsengine/internal/tool/semgrep"
	_ "github.com/ClatTribe/tsengine/internal/tool/sqlmap"
	_ "github.com/ClatTribe/tsengine/internal/tool/subfinder"
	_ "github.com/ClatTribe/tsengine/internal/tool/syft"
	_ "github.com/ClatTribe/tsengine/internal/tool/trivy"
	_ "github.com/ClatTribe/tsengine/internal/tool/trufflehog"
	_ "github.com/ClatTribe/tsengine/internal/tool/wpscan"
)

type assetCase struct {
	name    string
	handler asset.Handler
	target  types.Asset
	surface []string // for ReconHandler.PlanFanout
	// findings feed EscalationPlanner. THIS FIELD IS THE POINT: escalation triggers are
	// signal-GATED (§5.3), so passing nil findings meant the depth tools were never
	// dispatched and their arg contracts were never checked. Only web produced any
	// escalation at all — from its surface-matched triggers — so hydra, kiterunner, inql,
	// codeql, mobsfscan and govulncheck had gone unvalidated since the guard was written,
	// which is precisely the silent mis-wired-arg class it exists to catch.
	findings []types.Finding
	// wantsEscalation asserts this asset MUST produce at least one escalation dispatch from
	// the fixture above. Without it the fixture can drift out of matching the triggers and
	// the guard goes quietly back to checking nothing — which is how it got here.
	wantsEscalation bool
}

func cases() []assetCase {
	return []assetCase{
		{name: "web", handler: webasset.NewHandler(),
			target: types.Asset{Type: types.AssetWebApplication, Target: "http://localhost:8080/",
				// Set Auth so PlanFanout also emits the seed_auth dispatch.
				Auth: &types.AuthConfig{LoginURL: "http://localhost:8080/login", Username: "u", Password: "p"}},
			// wp-login.php in the surface exercises the wordpress→wpscan escalation.
			surface:         []string{"http://localhost:8080/", "http://localhost:8080/x?id=1", "http://localhost:8080/wp-login.php"},
			wantsEscalation: true},
		{name: "api", handler: apiasset.NewHandler(),
			target: types.Asset{Type: types.AssetAPI, Target: "http://localhost:8080/"},
			// /graphql in the surface trips the graphql→inql escalation.
			surface: []string{"SPEC http://localhost:8080/openapi.json", "GET http://localhost:8080/users/{id}",
				"POST http://localhost:8080/users", "POST http://localhost:8080/graphql"},
			// a spec-found finding trips spec→kiterunner
			findings: []types.Finding{{RuleID: "openapi_spec_ingest::spec-found", Tool: "openapi_spec_ingest",
				Endpoint: "http://localhost:8080/openapi.json"}},
			wantsEscalation: true},
		{name: "domain", handler: domainasset.NewHandler(),
			target:  types.Asset{Type: types.AssetDomain, Target: "example.com"},
			surface: []string{"example.com", "a.example.com", "b.example.com"},
			// An httpx fingerprint on a discovered subdomain — what PlanFanout really
			// produces, and what the threat-informed escalation reads. No wantsEscalation:
			// that stage is corpus-driven, and this test runs without one configured, so it
			// legitimately dispatches nothing here. The domain package's own tests cover the
			// with-corpus path.
			findings: []types.Finding{{RuleID: "httpx::probe", Tool: "httpx",
				Endpoint: "https://a.example.com",
				ToolArgs: map[string]string{"webserver": "Apache/2.4.49"}}}},
		{name: "cloud", handler: cloudasset.NewHandler(),
			target: types.Asset{Type: types.AssetCloudAccount, Target: "aws"}},
		{name: "ip", handler: ipasset.NewHandler(),
			target: types.Asset{Type: types.AssetIPAddress, Target: "127.0.0.1"},
			// :22 is an auth service, which is what trips auth-service→hydra. Without it the
			// surface holds only web ports and the escalation never fires.
			surface:         []string{"127.0.0.1:80", "127.0.0.1:443", "127.0.0.1:22"},
			wantsEscalation: true},
		{name: "repository", handler: repoasset.NewHandler(),
			target: types.Asset{Type: types.AssetRepository, Target: "/workspace"},
			// One finding per escalation trigger: a semgrep injection hit (→codeql, which also
			// needs a path whose extension maps to a language), a mobile-project file
			// (→mobsfscan) and a Go manifest (→govulncheck).
			findings: []types.Finding{
				{RuleID: "semgrep::sqli", Tool: "semgrep", CWE: []string{"CWE-89"}, Endpoint: "src/app.py:12"},
				{RuleID: "semgrep::mobile", Tool: "semgrep", Endpoint: "app/AndroidManifest.xml"},
				{RuleID: "osv::CVE-2024-1", Tool: "osv-scanner", Endpoint: "go.mod"},
			},
			wantsEscalation: true},
		{name: "container", handler: containerasset.NewHandler(),
			target: types.Asset{Type: types.AssetContainerImage, Target: "nginx:latest"}},
		{name: "mobile", handler: mobileasset.NewHandler(),
			target: types.Asset{Type: types.AssetMobileApplication, Target: "/workspace"}},
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
		// EscalationPlanner: depth dispatches off the surface/findings.
		if ep, ok := c.handler.(asset.EscalationPlanner); ok {
			esc := ep.PlanEscalation(c.target, c.surface, c.findings)
			if len(esc) == 0 && c.wantsEscalation {
				t.Errorf("[%s] PlanEscalation produced NO dispatches, so no escalation arg was checked — "+
					"the fixture no longer trips this asset's triggers and the guard has gone silent", c.name)
			}
			for _, d := range esc {
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
