package webagent

import (
	"strings"
	"testing"
)

// The prompt used to name its goal as "SQL injection, reflected XSS, open redirect" — three classes —
// while the engine grounds ~25. The agent was told to look for a fraction of what it can actually
// prove, which caps coverage on any benchmark that scores real CVEs across the wider set.
func TestPrompt_AdvertisesTheClassesTheEngineCanActuallyGround(t *testing.T) {
	p := buildPrompt(&Context{Target: "https://t.example.com", req: NewRequester([]string{"t.example.com"}, 50, 0)}, nil)
	low := strings.ToLower(p)

	// Classes the engine grounds but the old goal line omitted. If the prompt never mentions them, the
	// agent is unlikely to pursue them.
	for _, class := range []string{"ssrf", "traversal", "rce", "ssti", "idor"} {
		if !strings.Contains(low, class) {
			t.Errorf("the prompt never mentions %q, though the engine can ground it — the agent will "+
				"under-pursue it", class)
		}
	}
}

// Every indicator the prompt teaches the agent to cite must be one the engine actually emits.
// Naming a phantom indicator would teach the agent to cite something that always fails grounding.
func TestPrompt_NamesOnlyRealIndicators(t *testing.T) {
	p := buildPrompt(&Context{Target: "https://t.example.com", req: NewRequester([]string{"t.example.com"}, 50, 0)}, nil)
	// Indicators referenced in the grounding-rule line.
	for _, ind := range []string{
		"sql_error", "sql_boolean", "reflected_input", "external_redirect", "file_disclosure",
		"oob_interaction", "cmd_output", "ssti_eval", "bola_confirmed", "privesc_confirmed",
	} {
		if !strings.Contains(p, ind) {
			continue // not every indicator has to be named, but any that IS must be real (checked next)
		}
		if _, ok := indicatorIsKnown(ind); !ok {
			t.Errorf("the prompt names indicator %q, which the engine does not emit — grounding on it "+
				"would always fail", ind)
		}
	}
}

// indicatorIsKnown reports whether any class in requiredIndicator expects this indicator, i.e. the
// engine can produce it as a grounding signal.
func indicatorIsKnown(ind string) (string, bool) {
	for class, wants := range requiredIndicator {
		for _, w := range wants {
			if w == ind {
				return class, true
			}
		}
	}
	return "", false
}
