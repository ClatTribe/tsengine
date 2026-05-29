// Package openapi is a pure-Go OpenAPI/Swagger spec-ingest recon Tool for
// the api asset. It fetches the spec from the target (or common spec
// paths), parses the operation inventory, and returns each operation as a
// recon surface entry "METHOD url" — the exact endpoint list the api
// PlanFanout fans detection across. Spec-ingest-FIRST (not crawl-first) is
// the api recon model: the spec is the authoritative endpoint inventory.
//
// No external binary (HTTP + JSON), so it works in any image. Registers
// via init().
package openapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// OpenAPI is the tool.Tool implementation.
type OpenAPI struct{}

// New constructs an OpenAPI wrapper.
func New() *OpenAPI { return &OpenAPI{} }

func (*OpenAPI) Name() string              { return "openapi_spec_ingest" }
func (*OpenAPI) SandboxExecution() bool    { return true }
func (*OpenAPI) MITRETechniques() []string { return []string{"T1595"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*OpenAPI) KnownArgs() []string { return []string{"target", "spec_url"} }

// commonSpecPaths are tried (in order) under the target when no explicit
// spec_url is given.
var commonSpecPaths = []string{
	"/openapi.json", "/swagger.json", "/v3/api-docs",
	"/swagger/v1/swagger.json", "/api-docs", "/openapi.yaml",
}

// Run fetches + parses an OpenAPI spec. Recognized args:
//
//	"target"   string — required, the API base URL.
//	"spec_url" string — optional explicit spec URL (else common paths are tried).
//
// Returns one DiscoveredURLs entry "METHOD url" per operation, plus an
// info finding recording the endpoint count.
func (*OpenAPI) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	if target == "" {
		return tool.Result{}, errors.New("openapi_spec_ingest: missing required arg 'target'")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	candidates := []string{}
	if su, _ := args["spec_url"].(string); strings.TrimSpace(su) != "" {
		candidates = append(candidates, su)
	} else {
		for _, p := range commonSpecPaths {
			candidates = append(candidates, target+p)
		}
	}

	var spec []byte
	var specURL string
	for _, c := range candidates {
		if b, ok := fetch(ctx, client, c); ok {
			spec, specURL = b, c
			break
		}
	}
	if spec == nil {
		// No spec found — graceful: no surface, the orchestrator falls back
		// to single-target anchors.
		return tool.Result{Output: "openapi_spec_ingest: no spec found"}, nil
	}

	ops := parseSpec(spec, target)
	findings := []types.SandboxEmittedFinding{{
		RuleID:          "openapi_spec_ingest::spec-found",
		Tool:            "openapi_spec_ingest",
		Severity:        types.SeverityInfo,
		Endpoint:        specURL,
		Title:           fmt.Sprintf("OpenAPI spec ingested: %d operations", len(ops)),
		MITRETechniques: []string{"T1595"},
		ToolArgs:        map[string]string{"operations": fmt.Sprintf("%d", len(ops))},
	}}
	// Lead the surface with a "SPEC <url>" marker so PlanFanout can hand
	// the resolved schema location to the spec-driven fuzzer (schemathesis)
	// without re-resolving it.
	surface := append([]string{SpecMarker + " " + specURL}, ops...)
	return tool.Result{Output: string(spec), Findings: findings, DiscoveredURLs: surface}, nil
}

// SpecMarker tags the resolved-spec-URL entry in the recon surface.
const SpecMarker = "SPEC"

func fetch(ctx context.Context, c *http.Client, url string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil || len(buf) > 8*1024*1024 { // 8MB cap
			break
		}
	}
	if !json.Valid(buf) {
		return nil, false // only JSON specs (YAML support is backlog)
	}
	return buf, true
}

// spec mirrors the OpenAPI shape we read. v3 uses servers[]; v2 (swagger)
// uses host + basePath. We derive the base from the target if absent.
type spec struct {
	Swagger  string `json:"swagger"`
	BasePath string `json:"basePath"`
	Servers  []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true,
	"delete": true, "head": true, "options": true,
}

// parseSpec returns sorted "METHOD url" operation entries.
func parseSpec(blob []byte, target string) []string {
	var s spec
	if json.Unmarshal(blob, &s) != nil {
		return nil
	}
	base := baseURL(s, target)
	var ops []string
	for path, methods := range s.Paths {
		for method := range methods {
			m := strings.ToLower(method)
			if !httpMethods[m] {
				continue
			}
			ops = append(ops, strings.ToUpper(m)+" "+base+path)
		}
	}
	sort.Strings(ops) // deterministic (CLAUDE.md §10)
	return ops
}

// baseURL resolves the API base: v3 servers[0] (if absolute), else the
// target (+ v2 basePath).
func baseURL(s spec, target string) string {
	if len(s.Servers) > 0 && strings.HasPrefix(s.Servers[0].URL, "http") {
		return strings.TrimRight(s.Servers[0].URL, "/")
	}
	base := target
	if s.BasePath != "" && s.BasePath != "/" {
		base = target + s.BasePath
	}
	return strings.TrimRight(base, "/")
}

func init() { tool.Register(New()) }
