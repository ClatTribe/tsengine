package adapters

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/replay"
	"github.com/ClatTribe/tsengine/internal/tool"
)

// Prober adapts the tool-replay API (internal/replay) to the L2
// dispatch_l2_probe tool. Per §9, dispatch_l2_probe is "a thin wrapper over
// /replay": depth via a deterministic re-fire of an L1/registry tool, pinned
// to the original scan's corpus + image digest — NOT raw shell (strix's
// `terminal`). The Lead gets depth without arbitrary code execution.
//
// SCOPE GATE: the LLM Lead is UNTRUSTED — a prompt-injected finding (its
// title/endpoint flows into the agent transcript) could try to redirect a
// probe at an out-of-scope or internal host (the cloud metadata endpoint, the
// host platform). So an LLM-chosen target override is checked against the
// scan's authorized scope before the tool re-fires. (The human security
// engineer's /replay "dig deeper" path in internal/replay is intentionally NOT
// gated this way — that operator is trusted to retarget; only this LLM-driven
// adapter is.)
type Prober struct {
	ScanID     string
	RunsDir    string
	Spawner    replay.Spawner
	Scope      []string // authorized targets (asset target + scope hosts); empty → no override allowed
	OutOfScope []string // explicit carve-outs that win over Scope
}

var _ l2.Prober = (*Prober)(nil)

// NewProber wires the prober to a scan: scanID + runsDir locate the original
// scan (for the reproducibility pin), spawner produces the sandbox, and
// scope/outOfScope bound where an LLM-chosen target override may point.
func NewProber(scanID, runsDir string, spawner replay.Spawner, scope, outOfScope []string) *Prober {
	return &Prober{ScanID: scanID, RunsDir: runsDir, Spawner: spawner, Scope: scope, OutOfScope: outOfScope}
}

// Probe implements l2.Prober. It maps the LLM's free-form args onto a
// replay.Request (pulling "target" out as the override), re-fires the tool
// via /replay, and renders the resulting findings into a compact summary the
// Lead can cite via update_finding(verified_by="dispatch_l2_probe:<tool>").
func (p *Prober) Probe(ctx context.Context, toolName string, args map[string]any) (string, error) {
	req := replay.Request{ScanID: p.ScanID, Tool: toolName, Args: tool.Args{}}
	for k, v := range args {
		if k == "target" {
			if s, ok := v.(string); ok {
				req.Target = s
				continue
			}
		}
		req.Args[k] = v
	}
	// Scope gate: refuse before firing if the LLM steered the override target — or any URL-bearing arg —
	// outside the authorized scan scope. This contains a prompt-injection's blast radius.
	for _, cand := range probeTargets(req.Target, args) {
		if !p.targetAllowed(cand) {
			return "", fmt.Errorf("dispatch_l2_probe refused: target %q is outside the authorized scan scope", cand)
		}
	}
	resp, err := replay.Replay(ctx, req, p.RunsDir, p.Spawner)
	if err != nil {
		return "", err
	}
	return renderProbe(toolName, resp), nil
}

// targetAllowed reports whether an LLM-chosen target may be probed. An empty target (no override) uses
// the scan's own target and is always allowed. An out-of-scope carve-out wins; otherwise the target must
// match an authorized scope entry — so an empty Scope denies every override (the secure default).
func (p *Prober) targetAllowed(target string) bool {
	if target == "" {
		return true
	}
	if matchesScope(target, p.OutOfScope) {
		return false
	}
	return matchesScope(target, p.Scope)
}

// urlArgKeys are the LLM-arg keys that carry a host/URL (besides "target", handled as req.Target) — the
// same set the sandbox loopback-rewrite recognizes. Each is scope-checked so a probe can't be retargeted
// via a side arg.
var urlArgKeys = []string{"url", "urls", "targets", "login_url"}

// probeTargets collects every host/URL the probe would hit: the override target + any URL-bearing arg.
func probeTargets(reqTarget string, args map[string]any) []string {
	var out []string
	if reqTarget != "" {
		out = append(out, reqTarget)
	}
	for _, k := range urlArgKeys {
		switch v := args[k].(type) {
		case string:
			if v != "" {
				out = append(out, v)
			}
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		case []string:
			out = append(out, v...)
		}
	}
	return out
}

// matchesScope reports whether target matches any scope entry (host, URL-prefix, or *.wildcard host).
// Mirrors internal/pentest's matcher; a shared scope package is the documented dedup.
func matchesScope(target string, entries []string) bool {
	h := scopeHostOf(target)
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "://") || strings.Contains(e, "/") { // URL-prefix entry
			if strings.HasPrefix(strings.ToLower(target), strings.ToLower(e)) {
				return true
			}
			continue
		}
		if strings.HasPrefix(e, "*.") { // wildcard host
			suffix := strings.ToLower(e[1:])
			lh := strings.ToLower(h)
			if strings.HasSuffix(lh, suffix) || lh == strings.TrimPrefix(suffix, ".") {
				return true
			}
			continue
		}
		if strings.EqualFold(h, e) || strings.EqualFold(target, e) { // bare host / IP / ARN
			return true
		}
	}
	return false
}

func scopeHostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return u.Hostname()
		}
	}
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

func renderProbe(toolName string, resp *replay.Response) string {
	if len(resp.Findings) == 0 {
		return fmt.Sprintf("%s replay (%s): no findings", toolName, resp.ReplayID)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s replay (%s): %d finding(s)", toolName, resp.ReplayID, len(resp.Findings))
	for i, f := range resp.Findings {
		if i >= 10 {
			fmt.Fprintf(&b, "\n  …+%d more", len(resp.Findings)-10)
			break
		}
		fmt.Fprintf(&b, "\n  [%s] %s", f.Severity, f.Title)
		if f.Endpoint != "" {
			fmt.Fprintf(&b, " — %s", f.Endpoint)
		}
	}
	return b.String()
}
