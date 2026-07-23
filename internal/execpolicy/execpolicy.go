// Package execpolicy is the per-dispatch capability envelope the L1 sandbox tool-server enforces.
//
// Before this, /execute authenticated a bearer token and then ran ANY registered tool with ANY args
// on ANY target. That trusts the caller completely: a compromised or miswired orchestrator could run
// sqlmap against an internal host, or a tool never authorized for the scan. The Hugging Face incident
// is the cautionary tale — a foothold on one worker chained outward.
//
// The fix is spawn-time, not request-time: the platform bakes a Policy into the container at creation
// (TSENGINE_EXEC_POLICY), the tool-server reads it ONCE at startup, and every /execute is validated
// against it. A later request cannot widen the policy — so even if the orchestrator is later
// compromised, the sandbox refuses out-of-scope tools/targets/volume. Widening requires re-spawning
// with a new policy, which is a separate, auditable act.
//
// Grounded + fail-safe: an ABSENT policy (nil) is permissive (dev/back-compat, the tool-server logs a
// warning) — the production spawn path always sets one. A PRESENT policy is deny-by-default within
// each dimension it constrains.
package execpolicy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Policy is the capability envelope for one sandbox. An empty slice/zero means "unconstrained in that
// dimension" — so a policy of just {MaxRequests: 200} bounds volume without pinning tools/targets.
type Policy struct {
	ScanID      string    `json:"scan_id,omitempty"`      // provenance only (the run this capability is bound to)
	Tenant      string    `json:"tenant,omitempty"`       // provenance only
	Tools       []string  `json:"tools,omitempty"`        // permitted tool names; empty = any
	Hosts       []string  `json:"hosts,omitempty"`        // permitted target hostnames (any port); empty = any
	MaxRequests int       `json:"max_requests,omitempty"` // per-container tool-run budget; 0 = unlimited
	NotAfter    time.Time `json:"not_after,omitempty"`    // capability expiry; zero = no expiry
}

// targetKeys are the arg keys that carry a network target — the SAME set the sandbox client rewrites
// for the loopback boundary (CLAUDE.md §5.2 C2), so scope enforcement and loopback rewrite never drift.
var targetKeys = []string{"target", "targets", "url", "urls", "host", "hosts", "login_url"}

// FromEnv parses TSENGINE_EXEC_POLICY. An empty value → (nil, nil): no policy, permissive. A malformed
// value is an ERROR (fail loud — a broken policy must not silently degrade to "run anything").
func FromEnv(raw string) (*Policy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var p Policy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("execpolicy: parse TSENGINE_EXEC_POLICY: %w", err)
	}
	return &p, nil
}

// Encode serialises the policy for injection into a container's env.
func (p *Policy) Encode() (string, error) {
	b, err := json.Marshal(p)
	return string(b), err
}

// Allow enforces the envelope for one dispatch: `count` is the number of tool runs already served under
// this policy. A nil policy is permissive. It is deny-by-default within each constrained dimension, and
// checks expiry → tool → budget → every target host. The first violation is returned.
func (p *Policy) Allow(toolName string, args map[string]any, count int, now time.Time) error {
	if p == nil {
		return nil
	}
	if !p.NotAfter.IsZero() && now.After(p.NotAfter) {
		return fmt.Errorf("execpolicy: capability expired at %s", p.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(p.Tools) > 0 && !contains(p.Tools, toolName) {
		return fmt.Errorf("execpolicy: tool %q is not permitted for this scan", toolName)
	}
	if p.MaxRequests > 0 && count >= p.MaxRequests {
		return fmt.Errorf("execpolicy: request budget (%d) exhausted for this scan", p.MaxRequests)
	}
	if len(p.Hosts) > 0 {
		for _, h := range HostsFromArgs(args) {
			if !hostAllowed(p.Hosts, h) {
				return fmt.Errorf("execpolicy: target %q is not in the authorized scope", h)
			}
		}
	}
	return nil
}

// HostsFromArgs extracts every target hostname referenced by a tool's args (across the target-like
// keys, each of which may hold a string, []string, or []any of URLs/host[:port]). Lowercased, deduped.
func HostsFromArgs(args map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if h := hostOf(v); h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, k := range targetKeys {
		switch v := args[k].(type) {
		case string:
			add(v)
		case []string:
			for _, s := range v {
				add(s)
			}
		case []any:
			for _, s := range v {
				if str, ok := s.(string); ok {
					add(str)
				}
			}
		}
	}
	return out
}

// hostOf extracts the bare hostname from a URL or host[:port]. Returns "" for anything hostless.
func hostOf(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
		return ""
	}
	// host[:port] — strip a trailing :port (but keep an IPv6 literal intact via the [..]: form)
	h := v
	if strings.HasPrefix(h, "[") { // [::1]:80
		if i := strings.Index(h, "]"); i >= 0 {
			return strings.ToLower(h[1:i])
		}
	}
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[:i], ":") {
		h = h[:i]
	}
	return strings.ToLower(h)
}

func hostAllowed(allowed []string, h string) bool {
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), h) {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
