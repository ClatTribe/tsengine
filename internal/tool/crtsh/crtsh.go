// Package crtsh enumerates subdomains from Certificate Transparency logs
// via the public crt.sh JSON API. It's a tsengine recon Tool for the
// domain asset — a second enumeration SOURCE that corroborates and
// extends subfinder/amass (CT logs surface hosts passive DNS misses).
//
// No external binary: it's a plain HTTPS GET, so it works in any image
// (registers via init()). strix reverted its in-house bucket-discovery as
// "avoidable reinvention" of OSS — crt.sh is different: it's a thin client
// over a public data source no installed tool wraps the same way, the same
// rationale strix used to KEEP its IMDS probe. SandboxExecution=true so
// the egress goes through the sandbox boundary like every other tool.
package crtsh

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

// CrtSh is the tool.Tool implementation.
type CrtSh struct{}

// New constructs a CrtSh wrapper.
func New() *CrtSh { return &CrtSh{} }

func (*CrtSh) Name() string              { return "crtsh" }
func (*CrtSh) SandboxExecution() bool    { return true }
func (*CrtSh) MITRETechniques() []string { return []string{"T1590.005"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*CrtSh) KnownArgs() []string { return []string{"target"} }

// crtEntry is one row of crt.sh's JSON output. name_value may carry
// multiple newline-separated names (the SAN list) per cert; common_name is
// the leaf CN.
type crtEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// Run queries crt.sh for certs issued to *.<target> and returns the unique
// subdomains as both findings and the recon surface.
//
// Recognized args:
//
//	"target" string — required, the apex domain (e.g. "example.com").
func (*CrtSh) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return tool.Result{}, errors.New("crtsh: missing required arg 'target'")
	}

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return tool.Result{}, fmt.Errorf("crtsh: build request: %w", err)
	}
	req.Header.Set("User-Agent", "tsengine-crtsh/1.0")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Network/availability failure shouldn't crash the scan — crt.sh is
		// flaky under load. Degrade to zero results.
		return tool.Result{Output: "crtsh request failed: " + err.Error()}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tool.Result{Output: fmt.Sprintf("crtsh status %d", resp.StatusCode)}, nil
	}

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return tool.Result{Output: "crtsh decode failed: " + err.Error()}, nil
	}

	hosts := uniqueHosts(entries, target)
	findings := make([]types.SandboxEmittedFinding, 0, len(hosts))
	for _, h := range hosts {
		findings = append(findings, types.SandboxEmittedFinding{
			RuleID:          "crtsh::subdomain-found",
			Tool:            "crtsh",
			Severity:        types.SeverityInfo,
			Endpoint:        h,
			Title:           "Subdomain discovered (CT log): " + h,
			Description:     "via certificate transparency (crt.sh)",
			MITRETechniques: []string{"T1590.005"},
			ToolArgs:        map[string]string{"source": "crt.sh"},
		})
	}
	return tool.Result{Findings: findings, DiscoveredURLs: hosts}, nil
}

// uniqueHosts flattens the SAN lists, drops wildcards, scopes to the apex,
// dedups, and sorts (deterministic for reproducibility, CLAUDE.md §10).
func uniqueHosts(entries []crtEntry, apex string) []string {
	seen := map[string]struct{}{}
	add := func(raw string) {
		h := strings.ToLower(strings.TrimSpace(raw))
		h = strings.TrimPrefix(h, "*.")
		if h == "" || strings.Contains(h, " ") {
			return
		}
		// Scope: keep only names under the apex.
		if h != apex && !strings.HasSuffix(h, "."+apex) {
			return
		}
		seen[h] = struct{}{}
	}
	for _, e := range entries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			add(raw)
		}
		add(e.CommonName)
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func init() { tool.Register(New()) }
