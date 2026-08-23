// Package apisample samples API responses and classifies what they return —
// the collection half of OWASP API3:2023 (excessive data exposure).
//
// It exists because internal/apiexposure can answer "does this body return data
// the caller should not have received" and nothing in the L1 api path had a body
// to hand it. The recon stage fetches the SPEC, the fan-out tools send payloads,
// and none of them keep a response.
//
// WHY A SANDBOX TOOL AND NOT HOST-SIDE CODE. §12.2 puts network probes in the
// sandbox, and openapi_spec_ingest is the precedent: a Go-native tool that makes
// its own HTTP, registers via init(), and needs no binary — so no image rebuild
// (§12.7 applies to tools that shell out; this one does not).
//
// WHAT IT WILL NOT DO, and these are the bounds that make it safe to run by
// default rather than behind the RoE gate:
//
//   - GET ONLY. Never POST/PUT/PATCH/DELETE. Sampling must not mutate a
//     customer's data, and an "excessive data exposure" check that creates a
//     record to look at is not a check, it is an incident.
//   - NO CREDENTIALS, ever. That is not a limitation, it is the measurement: the
//     finding apiexposure can ground is "this came back to a caller with no
//     credentials", and sending some would destroy the thing being observed.
//   - BOUNDED. At most maxEndpoints URLs, one request each, a capped read and a
//     per-request timeout. One scan cannot become load generation — the failure
//     mode ADR 0026 refuses for API4.
//   - NO REDIRECT FOLLOWING. A 30x to an unrelated host would sample something
//     that was never in scope.
package apisample

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/apiexposure"
	"github.com/ClatTribe/tsengine/internal/tool"
)

const (
	// maxEndpoints bounds how many operations one dispatch samples.
	maxEndpoints = 25
	// maxBody mirrors apiauthz.HTTPProber — enough to classify, not enough to
	// let one response dominate memory.
	maxBody = 64 << 10
	// perRequest is the deadline for a single sample. The scan's own --timeout
	// remains the only overall deadline (§5.2 C3).
	perRequest = 8 * time.Second
)

// APISample is the tool.Tool implementation.
type APISample struct{}

// New constructs an APISample wrapper.
func New() *APISample { return &APISample{} }

func (*APISample) Name() string           { return "api_response_sample" }
func (*APISample) SandboxExecution() bool { return true }

// T1595 (Active Scanning) — the same technique openapi_spec_ingest reports; this
// reads declared endpoints rather than probing for undeclared ones.
func (*APISample) MITRETechniques() []string { return []string{"T1595"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec, §5.2 C4 — a CI test
// asserts every key a Handler dispatches is declared here).
func (*APISample) KnownArgs() []string { return []string{"targets"} }

// Run samples each URL with an unauthenticated GET and classifies the bodies.
//
//	"targets" string — required, newline-separated URLs (nuclei's list-mode shape).
//
// A target that does not answer, answers non-JSON, or returns nothing classifiable
// contributes no finding. A clean API produces an empty result, not a clean bill of
// health — this tool reports what it SAW, and §10's distinction between "we looked
// and it was fine" and "we could not look" is why an unreachable endpoint is simply
// absent rather than recorded as safe.
func (*APISample) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	raw, _ := args["targets"].(string)
	urls := splitTargets(raw)
	if len(urls) == 0 {
		return tool.Result{}, errors.New("api_response_sample: missing required arg 'targets'")
	}
	if len(urls) > maxEndpoints {
		urls = urls[:maxEndpoints]
	}

	client := &http.Client{
		Timeout: perRequest,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // do not follow: a 30x may leave scope
		},
	}

	var samples []apiexposure.Response
	for _, u := range urls {
		if ctx.Err() != nil {
			break // the scan deadline is the only overall clock
		}
		body, status, ok := get(ctx, client, u)
		if !ok {
			continue
		}
		samples = append(samples, apiexposure.Response{
			Endpoint: u,
			Status:   status,
			Body:     body,
			// Deliberately false and not a parameter: this tool never sends a
			// credential, so saying otherwise would misreport the one observation
			// the finding turns on.
			Authenticated: false,
		})
	}

	return tool.Result{Findings: apiexposure.Assess(samples)}, nil
}

func get(ctx context.Context, c *http.Client, url string) (string, int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, false
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		return "", 0, false
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return "", 0, false
	}
	return string(b), res.StatusCode, true
}

// splitTargets accepts the newline-separated list PlanFanout builds, and tolerates
// the "METHOD url" shape the spec ingest emits by taking only GET operations —
// sampling a declared DELETE would be a mutation, which this tool does not do.
func splitTargets(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if method, rest, found := strings.Cut(line, " "); found {
			if !strings.EqualFold(strings.TrimSpace(method), http.MethodGet) {
				continue
			}
			line = strings.TrimSpace(rest)
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}

func init() { tool.Register(New()) }
