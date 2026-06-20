// Package wpscan wraps WPScan — the dominant OSS WordPress security
// scanner — as a tsengine depth Tool for the web_application asset.
//
// WordPress runs a large share of SMB websites, and generic DAST (nuclei,
// dalfox, sqlmap) under-covers the CMS-specific attack surface: vulnerable
// plugins/themes (the #1 real WordPress compromise vector), core-version
// CVEs, user enumeration (fuels credential-stuffing), and exposed artifacts
// (wp-config backups, debug.log, db exports, directory listings). WPScan is
// purpose-built for exactly this.
//
// It is a registry-tier tool surfaced two ways (CLAUDE.md §9): the web
// escalation stage fires it ONLY when the crawl surface looks like
// WordPress (signal-gated depth, §5.3), and the tool-replay API can invoke
// it on demand. Findings are grounded in WPScan's own output — vulnerable
// components carry their CVE references, which the L1.5 threat_intel hook
// then enriches (KEV/EPSS). Registers via init().
package wpscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// WPScan is the tool.Tool implementation.
type WPScan struct{}

// New constructs a WPScan wrapper.
func New() *WPScan { return &WPScan{} }

func (*WPScan) Name() string              { return "wpscan" }
func (*WPScan) SandboxExecution() bool    { return true }
func (*WPScan) MITRETechniques() []string { return []string{"T1190", "T1592"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec). "target" is
// the WordPress site URL (loopback-rewritten at the sandbox boundary).
func (*WPScan) KnownArgs() []string { return []string{"target"} }

// Run scans a WordPress site. Recognized args:
//
//	"target" string — required, the site URL.
//
// Runs non-interactively, enumerating vulnerable plugins+themes and users
// (-e vp,vt,u). A free WPScan API token (env WPSCAN_API_TOKEN), if present,
// unlocks the vulnerability database for CVE-level detail — optional; without
// it WPScan still enumerates versions, interesting findings, and users.
func (*WPScan) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("wpscan: missing required arg 'target'")
	}
	argv := []string{
		"--url", target,
		"--format", "json",
		"--no-banner",
		"--random-user-agent",
		"--disable-tls-checks",
		"-e", "vp,vt,u",
	}
	if tok := strings.TrimSpace(os.Getenv("WPSCAN_API_TOKEN")); tok != "" {
		argv = append(argv, "--api-token", tok)
	}
	cmd := exec.CommandContext(ctx, "wpscan", argv...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	// WPScan exits non-zero (e.g. 5) when it FINDS vulnerabilities — that is a
	// successful scan, not an error. Only a non-ExitError (binary missing,
	// context cancelled) is a real failure; otherwise parse stdout regardless.
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "wpscan: " + err.Error()}, nil
		}
	}
	out := stdout.Bytes()
	return tool.Result{Output: string(out), Findings: parse(out, target)}, nil
}

// report mirrors the high-signal subset of WPScan's JSON. WPScan's full
// schema is large and irregular; we decode only the fields that carry a
// grounded finding.
type report struct {
	Version    *component           `json:"version"`
	MainTheme  *component           `json:"main_theme"`
	Plugins    map[string]component `json:"plugins"`
	Themes     map[string]component `json:"themes"`
	Interest   []interestingFinding `json:"interesting_findings"`
	Users      map[string]struct{}  `json:"users"`
	ConfigBaks map[string]struct{}  `json:"config_backups"`
	DBExports  map[string]struct{}  `json:"db_exports"`
}

type component struct {
	Slug    string `json:"slug"`
	Number  string `json:"number"`
	Version *struct {
		Number string `json:"number"`
	} `json:"version"`
	Vulns []vulnerability `json:"vulnerabilities"`
}

type vulnerability struct {
	Title      string `json:"title"`
	FixedIn    string `json:"fixed_in"`
	References struct {
		CVE []string `json:"cve"`
		URL []string `json:"url"`
	} `json:"references"`
}

type interestingFinding struct {
	URL  string `json:"url"`
	Type string `json:"type"`
	ToS  string `json:"to_s"`
}

func parse(blob []byte, target string) []types.SandboxEmittedFinding {
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding

	// Core / theme / plugin vulnerabilities — the high-value findings. Each
	// vuln is component-attributed and carries its CVE refs (threat_intel
	// enriches them downstream).
	if r.Version != nil {
		out = append(out, componentVulns("WordPress core", r.Version.Vulns, target)...)
	}
	if r.MainTheme != nil {
		out = append(out, componentVulns("theme "+r.MainTheme.Slug, r.MainTheme.Vulns, target)...)
	}
	for slug, c := range r.Themes {
		out = append(out, componentVulns("theme "+pick(slug, c.Slug), c.Vulns, target)...)
	}
	for slug, c := range r.Plugins {
		out = append(out, componentVulns("plugin "+pick(slug, c.Slug), c.Vulns, target)...)
	}

	// Exposed artifacts (interesting findings). Config/db/backup/debug
	// exposures are sensitive-data leaks; the rest are informational.
	for _, f := range r.Interest {
		sev := types.SeverityInfo
		if isSensitiveExposure(f.Type, f.ToS) {
			sev = types.SeverityHigh
		}
		title := strings.TrimSpace(f.ToS)
		if title == "" {
			title = "WordPress: " + f.Type
		}
		ep := f.URL
		if ep == "" {
			ep = target
		}
		out = append(out, types.SandboxEmittedFinding{
			RuleID:   "wpscan::interesting::" + f.Type,
			Tool:     "wpscan",
			Severity: sev,
			Endpoint: ep,
			Title:    title,
		})
	}

	// Username enumeration — aids credential-stuffing / brute force.
	if len(r.Users) > 0 {
		out = append(out, types.SandboxEmittedFinding{
			RuleID:          "wpscan::user-enumeration",
			Tool:            "wpscan",
			Severity:        types.SeverityLow,
			Endpoint:        target,
			Title:           "WordPress usernames are enumerable (" + joinKeys(r.Users) + ")",
			CWE:             []string{"CWE-200"},
			MITRETechniques: []string{"T1592"},
		})
	}
	return out
}

func componentVulns(label string, vulns []vulnerability, target string) []types.SandboxEmittedFinding {
	var out []types.SandboxEmittedFinding
	for _, v := range vulns {
		// Encode the CVE into the rule_id ("wpscan::CVE-2021-24000") so the
		// L1.5 threat_intel hook extracts + enriches it (KEV/EPSS), matching
		// the trivy/grype convention. One finding per CVE; vulns with no CVE
		// emit a single titled finding.
		cves := normalizeCVEs(v.References.CVE)
		if len(cves) == 0 {
			out = append(out, types.SandboxEmittedFinding{
				RuleID:          "wpscan::vuln",
				Tool:            "wpscan",
				Severity:        types.SeverityHigh,
				Endpoint:        target,
				Title:           label + ": " + v.Title,
				MITRETechniques: []string{"T1190"},
			})
			continue
		}
		for _, cve := range cves {
			out = append(out, types.SandboxEmittedFinding{
				RuleID:          "wpscan::" + cve,
				Tool:            "wpscan",
				Severity:        types.SeverityHigh,
				Endpoint:        target,
				Title:           label + ": " + v.Title,
				MITRETechniques: []string{"T1190"},
			})
		}
	}
	return out
}

// isSensitiveExposure flags interesting-finding types that leak sensitive
// data (config/db backups, debug logs) as opposed to informational ones
// (headers, robots.txt, readme, xmlrpc presence).
func isSensitiveExposure(typ, desc string) bool {
	s := strings.ToLower(typ + " " + desc)
	for _, k := range []string{"config_backup", "db_export", "backup", "debug_log", "wp-config", "database"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// normalizeCVEs prefixes bare WPScan CVE ids ("2021-24000") with "CVE-".
func normalizeCVEs(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(c), "CVE-") {
			c = "CVE-" + c
		}
		out = append(out, c)
	}
	return out
}

func pick(a, b string) string {
	if strings.TrimSpace(b) != "" {
		return b
	}
	return a
}

func joinKeys(m map[string]struct{}) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	if len(keys) > 5 {
		keys = append(keys[:5], "…")
	}
	return strings.Join(keys, ", ")
}

func init() { tool.Register(New()) }
