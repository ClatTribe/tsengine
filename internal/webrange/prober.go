package webrange

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Prober is a deterministic stand-in for the LLM brain: a blind, systematic
// attacker. For every route on the surface it tries every class's canonical
// payload, reads the engine's reported indicators, and records ONLY what an
// indicator proves — then confirms and finishes. It has zero knowledge of which
// routes are vulnerable, so a 100%-recall / 0-decoy result is a property of the
// engine's grounding, not of the attacker. It implements cloudengine.LLM, so it
// drops straight into webagent.Investigate in place of Gemini (CI-safe, no key).
type Prober struct {
	probes  []probeItem
	pi      int
	last    *probeItem
	phase   int // 0 probe, 1 record, 2 confirm, 3 finish
	noted   map[string]bool
	seen    map[string]bool // (route|class) already queued for record
	pending []pendRec
	confirm []string
	findN   int
}

type probeItem struct {
	sendURL   string // route + encoded payload
	route     string // clean route recorded on the finding
	class     string
	payload   string
	indicator string
}

type pendRec struct{ turnID, route, class string }

// classPayloads is the blind attacker's per-class payload set (XSS carries a
// WAF-bypass alternate). Each maps to the indicator that would prove it.
var classPayloads = []struct {
	class, payload, indicator string
}{
	{ClassSQLi, "'", "sql_error"},
	{ClassXSS, "<script>alert(1)</script>", "reflected_input"},
	{ClassXSS, "\"><img src=x onerror=alert(1)>", "reflected_input"},
	{ClassRedirect, "https://attacker.example/", "external_redirect"},
	{ClassPathTrav, "../../../../etc/passwd", "file_disclosure"},
	{ClassCmdi, "127.0.0.1;id", "cmd_output"},
}

// NewProber builds a prober over a set of full surface routes (each ending in
// "...param="). It probes every route with every class payload.
func NewProber(routes []string) *Prober {
	p := &Prober{noted: map[string]bool{}, seen: map[string]bool{}}
	for _, route := range routes {
		for _, cp := range classPayloads {
			p.probes = append(p.probes, probeItem{
				sendURL:   route + url.QueryEscape(cp.payload),
				route:     route,
				class:     cp.class,
				payload:   cp.payload,
				indicator: cp.indicator,
			})
		}
	}
	return p
}

var obsRe = regexp.MustCompile(`t-(\d{3})\s+status=\d+\s+indicators=\[([^\]]*)\]`)

func latestObs(prompt string) (turnID, inds string) {
	m := obsRe.FindAllStringSubmatch(prompt, -1)
	if len(m) == 0 {
		return "", ""
	}
	last := m[len(m)-1]
	return "t-" + last[1], last[2]
}

func action(tool string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{"thought": "prober", "tool": tool, "args": args})
	return string(b)
}

// Generate is the cloudengine.LLM entrypoint: one JSON action per call.
func (p *Prober) Generate(_ context.Context, prompt string) (string, error) {
	// correlate the send we just made
	if p.last != nil {
		tid, inds := latestObs(prompt)
		key := p.last.route + "|" + p.last.class
		if tid != "" {
			if strings.Contains(inds, "blocked_") {
				p.noted[p.last.route] = true
			}
			if strings.Contains(inds, p.last.indicator) && !p.seen[key] {
				p.seen[key] = true
				p.pending = append(p.pending, pendRec{tid, p.last.route, p.last.class})
			}
		}
		p.last = nil
	}

	switch p.phase {
	case 0: // PROBE
		for p.pi < len(p.probes) {
			it := p.probes[p.pi]
			p.pi++
			// skip the second XSS vector if the first already grounded this route
			if p.seen[it.route+"|"+it.class] {
				continue
			}
			p.last = &it
			args := map[string]any{"method": "GET", "url": it.sendURL}
			if it.payload != "" {
				args["payload"] = it.payload
			}
			return action("send_request", args), nil
		}
		p.phase = 1
		fallthrough
	case 1: // RECORD (grounded)
		if len(p.pending) > 0 {
			r := p.pending[0]
			p.pending = p.pending[1:]
			p.findN++
			p.confirm = append(p.confirm, fmt.Sprintf("web-%03d", p.findN))
			return action("record_finding", map[string]any{
				"route": r.route, "class": r.class, "evidence": []any{r.turnID},
				"severity": "high", "rationale": "indicator-proven by the prober",
			}), nil
		}
		p.phase = 2
		fallthrough
	case 2: // CONFIRM
		if len(p.confirm) > 0 {
			id := p.confirm[0]
			p.confirm = p.confirm[1:]
			return action("confirm_exploit", map[string]any{"finding_id": id}), nil
		}
		p.phase = 3
		fallthrough
	default: // FINISH
		return action("finish", map[string]any{"summary": "prober sweep complete"}), nil
	}
}
