package api

import (
	// Blank imports register the wrappers in THIS test binary. Without them tool.Get returns
	// nothing and the fan-out test skips — which is how a vacuous test passes as a real one.
	"context"
	_ "github.com/ClatTribe/tsengine/internal/tool/sqlmap"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/inql"
	_ "github.com/ClatTribe/tsengine/internal/tool/kiterunner"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	_ "github.com/ClatTribe/tsengine/internal/tool/openapi"
	_ "github.com/ClatTribe/tsengine/internal/tool/schemathesis"
)

func TestRegistryTier_ResolvesDigDeeperTools(t *testing.T) {
	// The api registry (on-demand replay tier) exposes kiterunner (shadow routes) + inql (GraphQL
	// introspection). Empty before — the "dig deeper" capability didn't exist for the api asset.
	got := names(NewHandler().Registry())
	want := map[string]bool{"kiterunner": true, "inql": true}
	for _, n := range got {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Errorf("api registry tier missing tools %v; got %v", want, got)
	}
}

func TestHandler_TypeAndAnchors(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetAPI {
		t.Errorf("Type: %q", h.Type())
	}
	if len(h.Anchors()) != 1 || h.Anchors()[0].Name() != "nuclei" {
		t.Errorf("Anchors: got %v, want [nuclei]", names(h.Anchors()))
	}
}

func TestPlanAnchors_AddsNucleiAPITags(t *testing.T) {
	h := NewHandler()
	out := h.PlanAnchors(types.Asset{Type: types.AssetAPI, Target: "https://api.example.com"})
	if len(out) != 1 {
		t.Fatalf("got %d dispatches", len(out))
	}
	// Assert the PROPERTY, not the literal: the protocol tags must be there, and so must the
	// exposure classes. Pinning the exact string made this test fail for the right change — an API
	// host serving /.env was going undetected because those templates were tagged out.
	tags, _ := out[0].Args["tags"].(string)
	for _, want := range []string{"api", "graphql", "jwt", "oauth", "exposure", "config"} {
		if !strings.Contains(tags, want) {
			t.Errorf("nuclei tags %q is missing %q — an API host leaks .env/.git like any web host, "+
				"and those templates only fire under the exposure/config tags", tags, want)
		}
	}
	if got := out[0].Args["target"]; got != "https://api.example.com" {
		t.Errorf("target arg lost: %v", got)
	}
}

func TestFilter_DropsHealthAndSpec(t *testing.T) {
	h := NewHandler()
	mk := func(target string) asset.Dispatch {
		return asset.Dispatch{Tool: &fakeTool{name: "nuclei"}, Args: tool.Args{"target": target}}
	}
	in := []asset.Dispatch{
		mk("https://api.example.com/v1/users"),
		mk("https://api.example.com/healthz"),
		mk("https://api.example.com/metrics"),
		mk("https://api.example.com/swagger.json"),
		mk("https://api.example.com/openapi.json"),
		mk("https://api.example.com/v3/api-docs"),
		mk("https://api.example.com/v1/orders"),
	}
	out := h.Filter(context.Background(), types.Asset{Type: types.AssetAPI}, in)
	if len(out) != 2 {
		t.Errorf("Filter kept %d; want 2 (v1/users + v1/orders)", len(out))
	}
}

func TestRecon_OffersOpenAPI(t *testing.T) {
	if len(NewHandler().Recon()) != 1 {
		t.Fatal("Recon() should offer openapi_spec_ingest when registered")
	}
}

func TestPlanRecon_PassesTarget(t *testing.T) {
	out := NewHandler().PlanRecon(types.Asset{Type: types.AssetAPI, Target: "https://api.x"})
	if len(out) != 1 || out[0].Args["target"] != "https://api.x" {
		t.Fatalf("PlanRecon = %+v", out)
	}
}

// PlanFanout: the SPEC marker → schemathesis; the operation URLs →
// nuclei list mode (deduped).
func TestPlanFanout_SpecFuzzAndSignatureScan(t *testing.T) {
	h := NewHandler()
	surface := []string{
		"SPEC https://api.x/openapi.json",
		"GET https://api.x/users/{id}",
		"POST https://api.x/users",
		"GET https://api.x/users/{id}", // dup endpoint
	}
	out := h.PlanFanout(types.Asset{Type: types.AssetAPI, Target: "https://api.x"}, surface)

	byTool := map[string]int{}
	var specURL, nucleiTargets, nucleiTags string
	for _, d := range out {
		byTool[d.Tool.Name()]++
		switch d.Tool.Name() {
		case "schemathesis":
			specURL, _ = d.Args["spec_url"].(string)
		case "nuclei":
			nucleiTargets, _ = d.Args["targets"].(string)
			nucleiTags, _ = d.Args["tags"].(string)
		}
	}
	if byTool["schemathesis"] != 1 || specURL != "https://api.x/openapi.json" {
		t.Errorf("schemathesis should run once on the resolved spec; got %d url=%q", byTool["schemathesis"], specURL)
	}
	if byTool["nuclei"] != 1 {
		t.Errorf("nuclei should run exactly once over the operation URLs; got %d", byTool["nuclei"])
	}
	for _, want := range []string{"api", "exposure"} {
		if !strings.Contains(nucleiTags, want) {
			t.Errorf("fan-out nuclei tags %q is missing %q", nucleiTags, want)
		}
	}
	// Endpoints deduped: the 2 spec operations PLUS the host itself.
	//
	// The host is not optional. Operations come only from what the spec DECLARES, so without it
	// anything served outside the spec — /.env, /.git, a backup, an admin panel — is never probed,
	// and a target that publishes a spec ends up LESS covered than one that does not. The web asset
	// has always included the target (§5.1 CollectSurface: target-always-included); this is api
	// catching up, and it was caught by a live scan missing a /.env full of credentials.
	got := splitLines(nucleiTargets)
	if len(got) != 3 {
		t.Errorf("nuclei targets = %q, want the 2 operations + the base host", nucleiTargets)
	}
	var hasHost bool
	for _, u := range got {
		if u == "https://api.x" {
			hasHost = true
		}
	}
	if !hasHost {
		t.Errorf("the host itself is missing from the fan-out (%q) — non-spec paths would go unscanned", nucleiTargets)
	}
}

func TestClassifyOp_PerMethodRouting(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		{"GET", "/users/{id}", ProbeIDOR},
		{"GET", "/users", ProbeGeneric},
		{"DELETE", "/sessions/{id}", ProbeBFLA},
		{"POST", "/users", ProbeMassAssignment},
		{"PUT", "/users/{id}", ProbeMassAssignment},
	}
	for _, c := range cases {
		if got := classifyOp(c.method, c.path); got != c.want {
			t.Errorf("classifyOp(%s %s) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestSplitOp(t *testing.T) {
	if m, u, ok := splitOp("GET https://api.x/a"); !ok || m != "GET" || u != "https://api.x/a" {
		t.Errorf("splitOp op failed: %s %s %v", m, u, ok)
	}
	if _, _, ok := splitOp("SPEC https://api.x/openapi.json"); ok {
		t.Error("SPEC marker should not parse as an operation")
	}
	if _, _, ok := splitOp("https://api.x"); ok {
		t.Error("bare URL should not parse as an operation")
	}
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, ln := range splitOnNewline(s) {
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

func splitOnNewline(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}

type fakeTool struct{ name string }

func (f *fakeTool) Name() string                                      { return f.name }
func (*fakeTool) SandboxExecution() bool                              { return true }
func (*fakeTool) MITRETechniques() []string                           { return nil }
func (*fakeTool) Run(context.Context, tool.Args) (tool.Result, error) { return tool.Result{}, nil }

func names(ts []tool.Tool) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name())
	}
	return out
}

// TestAPINucleiTags_IncludeInjection pins the class the tag set silently excluded.
//
// The set described how an API authenticates (api, graphql, jwt, oauth) and what it accidentally
// serves (exposure, config, files, misconfig) — and nothing about what it does with INPUT. Measured
// against VAmPI, whose headline documented vulnerability is SQL injection: recall 0.000, MISSED sqli.
//
// An API takes attacker-controlled input in path params, query strings and JSON bodies exactly like
// a web app, and injection is OWASP API Top 10. This is the second time this tag set was found to be
// missing a whole class — the exposure tags were added after a live target leaked DB_PASSWORD via
// /.env while the scan reported one informational finding.
func TestAPINucleiTags_IncludeInjection(t *testing.T) {
	for _, tag := range []string{"sqli", "injection", "xss", "ssrf", "lfi", "rce", "traversal"} {
		if !strings.Contains(apiNucleiTags, tag) {
			t.Errorf("apiNucleiTags is missing %q.\nAn API is injectable like any web app; omitting "+
				"the injection classes means nuclei never runs a single injection template against "+
				"an API surface.", tag)
		}
	}
	// The protocol and exposure classes must survive — both were added for measured reasons.
	for _, tag := range []string{"api", "graphql", "jwt", "oauth", "exposure", "config"} {
		if !strings.Contains(apiNucleiTags, tag) {
			t.Errorf("apiNucleiTags lost %q — that class was added after a live miss and must stay", tag)
		}
	}
}

// TestHasInjectableParams_CoversRESTShapes pins what counts as injectable on an API surface.
//
// A query-string-only test (what the web asset uses) finds almost nothing on REST, which expresses
// inputs as /users/v1/{username} rather than ?username=. Both the spec's brace form and a concrete
// numeric id are injectable; a static collection path is not, and fanning sqlmap across those is the
// per-URL trap that makes a scan miss its deadline.
func TestHasInjectableParams_CoversRESTShapes(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://api.x/search?q=1", true},          // query param
		{"https://api.x/users/v1/{username}", true}, // spec-declared path param
		{"https://api.x/books/v1/42", true},         // concrete object id
		{"https://api.x/users/v1", false},           // static collection
		{"https://api.x/", false},                   // root
		{"https://api.x/health", false},             // static endpoint
	} {
		if got := hasInjectableParams(tc.url); got != tc.want {
			t.Errorf("hasInjectableParams(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// The spec's operations must actually reach an injection tool. Before this, api dispatched only
// schemathesis + nuclei, so no injection payload was ever sent to an API endpoint — nuclei's
// injection templates are signature-based and find known product CVEs, not first-party SQLi.
func TestPlanFanout_DispatchesInjectionOnParamEndpoints(t *testing.T) {
	h := NewHandler()
	if _, ok := toolGet("sqlmap"); !ok {
		t.Fatal("sqlmap is blank-imported by this test file, so a miss here means the wrapper no " +
			"longer registers under that name — the fan-out would silently dispatch nothing")
	}
	out := h.PlanFanout(types.Asset{Type: types.AssetAPI, Target: "https://api.x/"}, []string{
		"SPEC https://api.x/openapi.json",
		"GET https://api.x/users/v1/{username}",
		"GET https://api.x/users/v1",
	})
	var sqlmapTargets []string
	for _, d := range out {
		if d.Tool.Name() == "sqlmap" {
			sqlmapTargets = append(sqlmapTargets, d.Args["target"].(string))
		}
	}
	if len(sqlmapTargets) == 0 {
		t.Fatal("no injection dispatch: a param-bearing endpoint must reach sqlmap, else the asset " +
			"never sends an injection payload at all")
	}
	for _, tgt := range sqlmapTargets {
		if strings.HasSuffix(tgt, "/users/v1") {
			t.Errorf("sqlmap fanned to a static collection path %q — that is the per-URL cost trap", tgt)
		}
	}
}

func toolGet(name string) (tool.Tool, bool) { return tool.Get(name) }
